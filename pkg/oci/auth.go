package oci

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	data, err := os.ReadFile(filepath.Join(home, ".docker", "config.json"))
	if err != nil {
		return Credentials{}, false
	}
	var config struct {
		Auths map[string]struct {
			Auth     string `json:"auth"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"auths"`
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
	return Credentials{}, false
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
	const prefix = "Bearer "
	if !strings.HasPrefix(strings.TrimSpace(header), prefix) {
		return bearerChallenge{}, false
	}
	params := parseAuthParams(strings.TrimSpace(header)[len(prefix):])
	realm := params["realm"]
	if realm == "" {
		return bearerChallenge{}, false
	}
	return bearerChallenge{Realm: realm, Service: params["service"], Scope: params["scope"]}, true
}

func parseAuthParams(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"`)
		out[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return out
}

func tokenRequestURL(challenge bearerChallenge, scope string) (string, error) {
	u, err := url.Parse(challenge.Realm)
	if err != nil {
		return "", err
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

func readBearerToken(client *http.Client, challenge bearerChallenge, scope string, creds Credentials, hasCreds bool) (string, error) {
	tokenURL, err := tokenRequestURL(challenge, scope)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, tokenURL, nil)
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
		text := strings.TrimSpace(string(data))
		if text == "" {
			text = resp.Status
		}
		return "", fmt.Errorf("token request failed: %s: %s: %s", resp.Status, tokenURL, text)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
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
