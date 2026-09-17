package adversary

import (
	"reflect"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
)

func TestReviewAssignmentForFilesPreservesOnlySpecialistScope(t *testing.T) {
	assignment := &detection.ReviewAssignment{ID: "group-002", Regions: []detection.ReviewRegion{
		{Path: "main.go", StartLine: 10, EndLine: 20},
		{Path: "web.ts", StartLine: 30, EndLine: 40},
	}}
	want := &detection.ReviewAssignment{ID: "group-002", Regions: []detection.ReviewRegion{
		{Path: "main.go", StartLine: 10, EndLine: 20},
	}}
	if got := reviewAssignmentForFiles(assignment, []string{"main.go"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("assignment = %#v, want %#v", got, want)
	}
	if got := reviewAssignmentForFiles(assignment, []string{"other.go"}); got != nil {
		t.Fatalf("inapplicable assignment = %#v, want nil", got)
	}
}
