package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Credentials struct {
	Username string
	Password string
	Token    string
}

type CredentialStore interface {
	Credentials(registry string) (Credentials, bool)
}

type DockerCredentialStore struct{}

func (DockerCredentialStore) Credentials(registry string) (Credentials, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Credentials{}, false
	}
	configFile, err := os.Open(filepath.Join(home, ".docker", "config.json"))
	if err != nil {
		return Credentials{}, false
	}
	defer configFile.Close()
	data, err := readLimited(configFile, 1<<20, "Docker config")
	if err != nil {
		return Credentials{}, false
	}
	var config struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
		CredentialHelpers map[string]string `json:"credHelpers"`
		CredentialsStore  string            `json:"credsStore"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return Credentials{}, false
	}
	for _, key := range dockerAuthKeys(registry) {
		auth, ok := config.Auths[key]
		if !ok {
			continue
		}
		if auth.Username != "" || auth.Password != "" {
			return Credentials{Username: auth.Username, Password: auth.Password}, true
		}
		if auth.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
			if err != nil {
				continue
			}
			username, password, ok := strings.Cut(string(decoded), ":")
			if ok {
				return Credentials{Username: username, Password: password}, true
			}
		}
	}
	for _, key := range dockerAuthKeys(registry) {
		helper := config.CredentialHelpers[key]
		if helper == "" {
			helper = config.CredentialsStore
		}
		if helper != "" {
			if creds, ok := credentialsFromHelper(helper, key); ok {
				return creds, true
			}
		}
	}
	return Credentials{}, false
}

func credentialsFromHelper(helper, server string) (Credentials, bool) {
	if strings.ContainsAny(helper, `/\\`) || strings.TrimSpace(helper) != helper || helper == "" {
		return Credentials{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker-credential-"+helper, "get")
	cmd.Stdin = strings.NewReader(server + "\n")
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return Credentials{}, false
	}
	out, readErr := readLimited(stdout, 1<<20, "credential helper output")
	if readErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return Credentials{}, false
	}
	if err := cmd.Wait(); err != nil {
		return Credentials{}, false
	}
	var result struct{ Username, Secret string }
	if json.Unmarshal(out, &result) != nil || result.Secret == "" {
		return Credentials{}, false
	}
	if result.Username == "<token>" {
		return Credentials{Token: result.Secret}, true
	}
	return Credentials{Username: result.Username, Password: result.Secret}, true
}

func dockerAuthKeys(registry string) []string {
	keys := []string{registry, "https://" + registry, "http://" + registry}
	if registry == "registry-1.docker.io" || registry == "index.docker.io" {
		keys = append(keys, "https://index.docker.io/v1/")
	}
	return keys
}

type bearerChallenge struct {
	Realm   string
	Service string
	Scope   string
}

func parseBearerChallenge(header string) (bearerChallenge, bool) {
	header = strings.TrimSpace(header)
	space := strings.IndexByte(header, ' ')
	if space < 0 || !strings.EqualFold(header[:space], "bearer") {
		return bearerChallenge{}, false
	}
	params := parseAuthParams(strings.TrimSpace(header[space+1:]))
	realm := params["realm"]
	if realm == "" {
		return bearerChallenge{}, false
	}
	return bearerChallenge{Realm: realm, Service: params["service"], Scope: params["scope"]}, true
}

func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	for len(strings.TrimSpace(s)) > 0 {
		s = strings.TrimSpace(s)
		comma, quoted, escaped := -1, false, false
		for i, ch := range s {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' && quoted {
				escaped = true
				continue
			}
			if ch == '"' {
				quoted = !quoted
				continue
			}
			if ch == ',' && !quoted {
				comma = i
				break
			}
		}
		part := s
		if comma >= 0 {
			part, s = s[:comma], s[comma+1:]
		} else {
			s = ""
		}
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = strings.ReplaceAll(strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`), `\\`, `\`)
		}
		out[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return out
}

func tokenRequestURL(challenge bearerChallenge, scope string) (string, error) {
	u, err := url.Parse(challenge.Realm)
	if err != nil {
		return "", err
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Host))) {
		return "", fmt.Errorf("bearer authentication realm must be HTTPS (or explicit loopback HTTP)")
	}
	q := u.Query()
	if challenge.Service != "" {
		q.Set("service", challenge.Service)
	}
	if scope == "" {
		scope = challenge.Scope
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func readBearerToken(ctx context.Context, client *http.Client, challenge bearerChallenge, scope string, creds Credentials, hasCreds bool) (string, error) {
	tokenURL, err := tokenRequestURL(challenge, scope)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	if hasCreds {
		ApplyAuthHeader(req, creds)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := readLimited(resp.Body, 64<<10, "token error response")
		text := sanitizeErrorText(string(data))
		if text == "" {
			text = resp.Status
		}
		u := req.URL
		endpoint := u.Scheme + "://" + u.Host + u.EscapedPath()
		return "", fmt.Errorf("token request failed: %s: %s: %s", resp.Status, endpoint, text)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	data, err := readLimited(resp.Body, 1<<20, "token response")
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", fmt.Errorf("token response did not include a bearer token")
}

func ApplyAuthHeader(req *http.Request, creds Credentials) {
	if creds.Token != "" {
		req.Header.Set("Authorization", "Bearer "+creds.Token)
		return
	}
	if creds.Username != "" || creds.Password != "" {
		req.SetBasicAuth(creds.Username, creds.Password)
	}
}

type ChainCredentialStore []CredentialStore

func (stores ChainCredentialStore) Credentials(registry string) (Credentials, bool) {
	for _, store := range stores {
		if store == nil {
			continue
		}
		if creds, ok := store.Credentials(registry); ok {
			return creds, true
		}
	}
	return Credentials{}, false
}
