package findingverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
)

func gitTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-C", root}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}
func repoFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	gitTest(t, root, "init")
	gitTest(t, root, "config", "user.name", "Fixture")
	gitTest(t, root, "config", "user.email", "fixture@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "guard.go"), []byte("old guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "base")
	base := gitTest(t, root, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(root, "guard.go"), []byte("new guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "head")
	return root, base, gitTest(t, root, "rev-parse", "HEAD")
}
func TestCollectorPinsCommitsAndFreezesDirtySource(t *testing.T) {
	root, base, head := repoFixture(t)
	ctx := context.Background()
	change := &detection.Context{RepositoryRoot: root, BaseRef: base, HeadRef: head, Mode: detection.ModeExplicitRange, ChangedFiles: []detection.ChangedFile{{Path: "guard.go", Status: detection.StatusModified}}}
	c, err := NewCollector(ctx, change)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "guard.go"), []byte("dirty guard\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ side, want string }{{"base", "old guard\n"}, {"head", "new guard\n"}} {
		s := c.Read(ctx, ReadRequest{Path: "guard.go", Side: tc.side, StartLine: 1, EndLine: 1})
		if s.Content != tc.want {
			t.Fatal(s)
		}
	}
	change.Mode = detection.ModeDirtyWorktree
	change.BaseRef = head
	dirty, err := NewCollector(ctx, change)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "guard.go"), []byte("later edit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := dirty.Read(ctx, ReadRequest{Path: "guard.go", Side: "head", StartLine: 1, EndLine: 1})
	if s.Content != "dirty guard\n" {
		t.Fatal(s)
	}
}
func TestCollectorRejectsTraversalSymlinksAndMissingSource(t *testing.T) {
	root, base, head := repoFixture(t)
	ctx := context.Background()
	c, err := NewCollector(ctx, &detection.Context{RepositoryRoot: root, BaseRef: base, HeadRef: head})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../outside", "/etc/passwd", ".git/config", "a/../guard.go", "missing.go", "guard.go\nother"} {
		s := c.Read(ctx, ReadRequest{Path: p, Side: "head", StartLine: 1, EndLine: 1})
		if s.Unavailable == "" {
			t.Fatalf("read %q: %+v", p, s)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("must not read"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skip("symlinks unavailable")
	}
	dirty, err := NewCollector(ctx, &detection.Context{RepositoryRoot: root, Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "linked", Status: detection.StatusUntracked}}})
	if err != nil {
		t.Fatal(err)
	}
	if s := dirty.Read(ctx, ReadRequest{Path: "linked", Side: "head", StartLine: 1, EndLine: 1}); s.Unavailable == "" {
		t.Fatal(s)
	}
}
