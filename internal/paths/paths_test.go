package paths

import (
	"path/filepath"
	"testing"
)

func TestDataDirPlatformDefaults(t *testing.T) {
	home := func() (string, error) { return filepath.FromSlash("/home/test"), nil }
	tests := []struct {
		os   string
		env  map[string]string
		want string
	}{
		{"linux", nil, filepath.FromSlash("/home/test/.local/share/adversary")},
		{"linux", map[string]string{"XDG_DATA_HOME": filepath.FromSlash("/xdg")}, filepath.FromSlash("/xdg/adversary")},
		{"darwin", nil, filepath.FromSlash("/home/test/Library/Application Support/Adversary")},
		{"windows", map[string]string{"LOCALAPPDATA": filepath.FromSlash("/local")}, filepath.FromSlash("/local/Adversary")},
	}
	for _, tc := range tests {
		t.Run(tc.os, func(t *testing.T) {
			got, err := dataDir(tc.os, func(k string) string { return tc.env[k] }, home)
			if err != nil || got != tc.want {
				t.Fatalf("DataDir() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestDataDirOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "custom")
	got, err := dataDir("linux", func(k string) string {
		if k == "ADVERSARY_DATA_DIR" {
			return override
		}
		return "ignored"
	}, func() (string, error) { return "ignored", nil })
	if err != nil || got != override {
		t.Fatalf("got %q, %v; want %q", got, err, override)
	}
}
