package adversary

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProcessEnvironmentNormalizesAndOverridesDeterministically(t *testing.T) {
	env := NewProcessEnvironment([]string{"Path=first", "PATH=second", "ADVERSARY_REPO=hostile", "Z=last"}, true)
	if got, _ := env.Lookup("path"); got != "second" {
		t.Fatalf("PATH = %q", got)
	}
	got := env.Entries(map[string]string{"adversary_repo": "owned", "A": "first"})
	want := []string{"A=first", "adversary_repo=owned", "PATH=second", "Z=last"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %#v, want %#v", got, want)
	}
}

func TestProcessEnvironmentRejectsUnsafePATHEntriesBeforeSelection(t *testing.T) {
	absolute := t.TempDir()
	for _, path := range []string{
		"",
		"relative" + string(os.PathListSeparator) + absolute,
		absolute + string(os.PathListSeparator),
	} {
		env := NewProcessEnvironment([]string{"PATH=" + path}, false)
		calls := 0
		_, err := env.LookPath("tool", func(candidate string) (string, error) {
			calls++
			return candidate, nil
		})
		if !errors.Is(err, ErrUnsafeCapturedPATH) || calls != 0 {
			t.Fatalf("PATH %q: error=%v resolver calls=%d", path, err, calls)
		}
	}
}

func TestProcessEnvironmentRequiresAbsoluteResolvedPath(t *testing.T) {
	env := NewProcessEnvironment([]string{"PATH=" + t.TempDir()}, false)
	_, err := env.LookPath("tool", func(string) (string, error) { return "relative/tool", nil })
	if err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("error = %v", err)
	}
}

func TestProcessEnvironmentLookupIgnoresLivePATHMutation(t *testing.T) {
	captured := t.TempDir()
	hostile := t.TempDir()
	env := NewProcessEnvironment([]string{"PATH=" + captured}, false)
	t.Setenv("PATH", hostile)
	got, err := env.LookPath("tool", func(candidate string) (string, error) { return candidate, nil })
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(captured, "tool")
	if got != want {
		t.Fatalf("resolved path = %q, want captured %q", got, want)
	}
}

func TestProcessEnvironmentUsesDefaultWindowsPATHEXT(t *testing.T) {
	dir := t.TempDir()
	env := NewProcessEnvironment([]string{"PATH=" + dir}, true)
	got, err := env.LookPath("tool", func(candidate string) (string, error) {
		if strings.HasSuffix(candidate, ".EXE") {
			return candidate, nil
		}
		return "", fs.ErrNotExist
	})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "tool.EXE")
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestProcessEnvironmentIsImmutable(t *testing.T) {
	source := []string{"PATH=/captured"}
	env := NewProcessEnvironment(source, false)
	source[0] = "PATH=/mutated"
	if got, _ := env.Lookup("PATH"); got != "/captured" {
		t.Fatalf("PATH = %q", got)
	}
}
