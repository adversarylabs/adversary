package adversarylabs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
)

const (
	DefaultRegistry = oci.DefaultRegistry
	DefaultAPIURL   = "https://adversarylabs.ai/api"
	expirySkew      = 30 * time.Second
)

func ResolveRegistryHost() string { return oci.DefaultRegistryHost() }

// AuthKey isolates credentials by API service and profile. The legacy registry
// key remains readable so existing installations and OCI credential lookup keep working.
func AuthKey(apiURL, profile string) string {
	service := strings.ToLower(strings.TrimRight(ResolveAPIURL(apiURL), "/"))
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		profile = "default"
	}
	return service + "#" + profile
}

type Config struct {
	Auths map[string]Auth `json:"auths"`
}
type Auth struct {
	Token             string `json:"token,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	RegistryHost      string `json:"registry_host,omitempty"`
	RegistryNamespace string `json:"registry_namespace,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Team              string `json:"team,omitempty"`
}
type ConfigStore struct{ Path string }

func DefaultConfigStore() (ConfigStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return ConfigStore{}, err
	}
	return ConfigStore{Path: filepath.Join(home, ".adversary", "config.json")}, nil
}

func (s ConfigStore) rejectSymlink() error {
	for _, p := range []string{filepath.Dir(s.Path), s.Path} {
		info, err := os.Lstat(p)
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || p == filepath.Dir(s.Path) && !info.IsDir() || p == s.Path && !info.Mode().IsRegular()) {
			return fmt.Errorf("refusing non-regular credential path %q", p)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (s ConfigStore) Load() (Config, error) {
	if err := s.rejectSymlink(); err != nil {
		return Config{}, err
	}
	if err := os.Chmod(filepath.Dir(s.Path), 0700); err != nil && !os.IsNotExist(err) {
		return Config{}, err
	}
	data, err := readCredentialFile(s.Path)
	if os.IsNotExist(err) {
		return Config{Auths: map[string]Auth{}}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read credentials: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse credentials: %w", err)
	}
	if config.Auths == nil {
		config.Auths = map[string]Auth{}
	}
	return config, nil
}

func (s ConfigStore) Save(config Config) error {
	return s.locked(func(current *Config) error { *current = config; return nil })
}

func (s ConfigStore) saveUnlocked(config Config) error {
	if err := s.rejectSymlink(); err != nil {
		return err
	}
	if config.Auths == nil {
		config.Auths = map[string]Auth{}
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.Path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s ConfigStore) locked(fn func(*Config) error) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	if err := s.rejectSymlink(); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(s.Path + ".lock"); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked credential lock %q", s.Path+".lock")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return withFileLock(s.Path+".lock", func() error {
		c, err := s.Load()
		if err != nil {
			return err
		}
		if err := fn(&c); err != nil {
			return err
		}
		return s.saveUnlocked(c)
	})
}

func (s ConfigStore) SetAuth(key string, auth Auth) error {
	return s.locked(func(c *Config) error { c.Auths[key] = auth; return nil })
}
func (s ConfigStore) RemoveAuth(key string) (Auth, bool, error) {
	var auth Auth
	var ok bool
	err := s.locked(func(c *Config) error {
		auth, ok = c.Auths[key]
		if ok {
			delete(c.Auths, key)
		}
		return nil
	})
	return auth, ok, err
}

func (s ConfigStore) AuthE(key string) (Auth, bool, error) {
	c, err := s.Load()
	if err != nil {
		return Auth{}, false, err
	}
	a, ok := c.Auths[key]
	if !ok && key == ResolveRegistryHost() {
		var match Auth
		matches := 0
		for _, candidate := range c.Auths {
			if candidate.RegistryHost == key {
				match, matches = candidate, matches+1
			}
		}
		if matches > 1 {
			return Auth{}, false, fmt.Errorf("ambiguous credentials for registry %q", key)
		}
		if matches == 1 {
			a, ok = match, true
		}
	}
	if !ok || a.Token == "" {
		return Auth{}, false, nil
	}
	return validateAuth(a)
}

// ExactAuthE never performs registry-host discovery and is used for API authorization.
func (s ConfigStore) ExactAuthE(key string) (Auth, bool, error) {
	c, err := s.Load()
	if err != nil {
		return Auth{}, false, err
	}
	a, ok := c.Auths[key]
	if !ok || a.Token == "" {
		return Auth{}, false, nil
	}
	return validateAuth(a)
}

func validateAuth(a Auth) (Auth, bool, error) {
	if a.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
		if err != nil {
			return Auth{}, false, fmt.Errorf("malformed credential expiration: %w", err)
		}
		if !time.Now().Add(expirySkew).Before(exp) {
			return Auth{}, false, nil
		}
	}
	return a, true, nil
}
func (s ConfigStore) Auth(key string) (Auth, bool) { a, ok, _ := s.AuthE(key); return a, ok }
func (s ConfigStore) Credentials(registry string) (oci.Credentials, bool) {
	a, ok, err := s.AuthE(registry)
	if err != nil || !ok {
		return oci.Credentials{}, false
	}
	return oci.Credentials{Token: a.Token}, true
}
