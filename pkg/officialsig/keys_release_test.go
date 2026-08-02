//go:build release

package officialsig

import (
	"testing"
)

func TestReleaseBuildKeyringIsProdOnly(t *testing.T) {
	restore := SetKeyringForTest(nil)
	t.Cleanup(restore)
	if BuildFlavor() != "release" {
		t.Fatalf("flavor=%q", BuildFlavor())
	}
	if DefaultKeyID != ProdKeyID {
		t.Fatalf("DefaultKeyID=%q want %q", DefaultKeyID, ProdKeyID)
	}
	keys := DefaultKeyring()
	if _, ok := keys[ProdKeyID]; !ok {
		t.Fatal("missing official-prod")
	}
	if _, ok := keys[DevKeyID]; ok {
		t.Fatal("release binary must not embed official-dev")
	}
}
