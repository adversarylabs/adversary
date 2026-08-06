package cmd

import (
	"testing"
)

func TestExpandComposeRefsNoCompose(t *testing.T) {
	refs := []string{"./x", "./y"}
	got, roots, err := expandComposeRefs(t.Context(), nil, refs, "", "", true, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || roots != nil {
		t.Fatalf("%#v %#v", got, roots)
	}
}
