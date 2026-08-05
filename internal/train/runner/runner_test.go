package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/bundle"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
)

func TestLockLocalPackageSerializes(t *testing.T) {
	dir := t.TempDir()
	unlock1 := LockLocalPackage(dir)
	done := make(chan struct{})
	go func() {
		unlock2 := LockLocalPackage(dir)
		close(done)
		unlock2()
	}()
	// unlock1 still held — goroutine should block
	select {
	case <-done:
		t.Fatal("should block while locked")
	default:
	}
	unlock1()
	<-done
}

func TestLockLocalPackageNoopForCatalogName(t *testing.T) {
	unlock := LockLocalPackage("engineering-review")
	unlock() // no panic
}

func TestRunBaselineFixture(t *testing.T) {
	dir := t.TempDir()
	fix := filepath.Join(dir, "base.json")
	body := `{"findings":[{"id":"1","claim":"x"}]}`
	if err := os.WriteFile(fix, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	proj := &bundle.Projection{
		Role:     bundle.RoleReviewer,
		Sections: map[string]bundle.Section{},
	}
	out := filepath.Join(dir, "out")
	res, err := RunBaseline(proj, out, fix)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExecutionClass != dataroot.ClassFixture {
		t.Fatalf("%+v", res)
	}
	if len(res.RawJSON) == 0 {
		t.Fatal("empty raw")
	}
	// also heuristic path (no fixture)
	res2, err := RunBaseline(proj, filepath.Join(dir, "out2"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.RawJSON) == 0 {
		t.Fatal("heuristic empty")
	}
}

func TestRunEngineeringReviewFixture(t *testing.T) {
	dir := t.TempDir()
	fix := filepath.Join(dir, "eng.json")
	_ = os.WriteFile(fix, []byte(`{"findings":[]}`), 0o600)
	pkg := t.TempDir()
	proj := &bundle.Projection{Role: bundle.RoleReviewer, Sections: map[string]bundle.Section{}}
	res, err := RunEngineeringReview(proj, filepath.Join(dir, "out"), "", "", "", pkg, fix)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.ExecutionClass != dataroot.ClassFixture {
		t.Fatalf("%+v", res)
	}
}
