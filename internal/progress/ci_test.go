package progress

import (
	"bytes"
	"fmt"
	"testing"
)

func TestCIProgress(t *testing.T) {
	for _, tc := range []struct {
		value   string
		concise bool
	}{
		{"", false}, {"false", false}, {"FALSE", false}, {"0", false},
		{"true", true}, {"1", true}, {" yes ", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("CI", tc.value)
			var out bytes.Buffer
			fmt.Fprintln(Detail(&out), "download detail")
			if got := out.Len() == 0; got != tc.concise {
				t.Fatalf("suppressed = %v, want %v", got, tc.concise)
			}
		})
	}
}
