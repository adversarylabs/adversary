// Package paths defines the CLI's platform storage contract.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const appName = "adversary"

// DataDir returns persistent artifact data. ADVERSARY_DATA_DIR overrides only
// this root; credentials and disposable caches remain separate.
func DataDir() (string, error) { return dataDir(runtime.GOOS, os.Getenv, os.UserHomeDir) }

func dataDir(goos string, getenv func(string) string, home func() (string, error)) (string, error) {
	if override := strings.TrimSpace(getenv("ADVERSARY_DATA_DIR")); override != "" {
		p, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolve ADVERSARY_DATA_DIR: %w", err)
		}
		return filepath.Clean(p), nil
	}
	h, err := home()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	switch goos {
	case "darwin":
		return filepath.Join(h, "Library", "Application Support", "Adversary"), nil
	case "windows":
		if base := strings.TrimSpace(getenv("LOCALAPPDATA")); base != "" {
			return filepath.Join(base, "Adversary"), nil
		}
		return filepath.Join(h, "AppData", "Local", "Adversary"), nil
	default:
		if base := strings.TrimSpace(getenv("XDG_DATA_HOME")); base != "" {
			return filepath.Join(base, appName), nil
		}
		return filepath.Join(h, ".local", "share", appName), nil
	}
}

func ConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config directory: %w", err)
	}
	return filepath.Join(base, appName), nil
}

func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate cache directory: %w", err)
	}
	return filepath.Join(base, appName), nil
}

func TempDir() string { return os.TempDir() }
