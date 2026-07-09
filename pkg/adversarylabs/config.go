package adversarylabs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
)

const (
	DefaultRegistry = oci.DefaultRegistry
	DefaultAPIURL   = "https://adversarylabs.ai/api"
)

func ResolveRegistryHost() string {
	return oci.DefaultRegistryHost()
}

type Config struct {
	Auths map[string]Auth `json:"auths"`
}

type Auth struct {
	Token             string `json:"token,omitempty"`
	ClientID          string `json:"client_id,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	RegistryNamespace string `json:"registry_namespace,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Team              string `json:"team,omitempty"`
}

type ConfigStore struct {
	Path string
}

func DefaultConfigStore() (ConfigStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return ConfigStore{}, err
	}
	return ConfigStore{Path: filepath.Join(home, ".adversary", "config.json")}, nil
}

func (s ConfigStore) Load() (Config, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return Config{Auths: map[string]Auth{}}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	if config.Auths == nil {
		config.Auths = map[string]Auth{}
	}
	return config, nil
}

func (s ConfigStore) Save(config Config) error {
	if config.Auths == nil {
		config.Auths = map[string]Auth{}
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(s.Path, data, 0600)
}

func (s ConfigStore) SetAuth(registry string, auth Auth) error {
	config, err := s.Load()
	if err != nil {
		return err
	}
	config.Auths[registry] = auth
	return s.Save(config)
}

func (s ConfigStore) RemoveAuth(registry string) (Auth, bool, error) {
	config, err := s.Load()
	if err != nil {
		return Auth{}, false, err
	}
	auth, ok := config.Auths[registry]
	if ok {
		delete(config.Auths, registry)
	}
	return auth, ok, s.Save(config)
}

func (s ConfigStore) Auth(registry string) (Auth, bool) {
	config, err := s.Load()
	if err != nil {
		return Auth{}, false
	}
	auth, ok := config.Auths[registry]
	if !ok || auth.Token == "" {
		return Auth{}, false
	}
	if auth.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, auth.ExpiresAt)
		if err == nil && time.Now().After(expiresAt) {
			return Auth{}, false
		}
	}
	return auth, true
}

func (s ConfigStore) Credentials(registry string) (oci.Credentials, bool) {
	auth, ok := s.Auth(registry)
	if !ok {
		return oci.Credentials{}, false
	}
	return oci.Credentials{Token: auth.Token}, true
}
