package reviewui

import (
	"fmt"
	"strings"
	"testing"
)

func TestContextWindowExpandsOutsideDiffHunk(t *testing.T) {
	file := make([]string, 30)
	for i := range file {
		file[i] = string(rune('a' + i%26))
	}
	hunk := "@@ -10,3 +10,4 @@ function run()"

	up, err := contextWindow(file, ContextRequest{DiffHunk: hunk, Direction: "up", Count: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(up.Lines) != 5 || up.Lines[0].Number != 5 || up.Lines[4].Number != 9 || !up.HasMore {
		t.Fatalf("up=%+v", up)
	}

	down, err := contextWindow(file, ContextRequest{DiffHunk: hunk, Direction: "down", Count: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(down.Lines) != 5 || down.Lines[0].Number != 14 || down.Lines[4].Number != 18 || !down.HasMore {
		t.Fatalf("down=%+v", down)
	}

	nextUp, err := contextWindow(file, ContextRequest{DiffHunk: hunk, Direction: "up", Offset: 5, Count: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(nextUp.Lines) != 4 || nextUp.Lines[0].Number != 1 || nextUp.Lines[3].Number != 4 || nextUp.HasMore {
		t.Fatalf("next up=%+v", nextUp)
	}
}

func TestRepositoryFromPRURL(t *testing.T) {
	owner, repo, err := repositoryFromPRURL("https://github.com/acme/widgets/pull/42")
	if err != nil || owner != "acme" || repo != "widgets" {
		t.Fatalf("owner=%q repo=%q err=%v", owner, repo, err)
	}
	if _, _, err := repositoryFromPRURL("https://github.com/acme/widgets"); err == nil {
		t.Fatal("expected invalid PR URL error")
	}
}

func TestEvidenceSourceWindowIncludesFullReviewedBody(t *testing.T) {
	file := make([]string, 320)
	for i := range file {
		file[i] = fmt.Sprintf("source line %d", i+1)
	}
	got, err := evidenceSourceWindow(file, ContextRequest{DiffHunk: "@@ -100,2 +100,2 @@ func runtimeObjectStore()"}, 240)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"80: source line 80", "100: source line 100", "319: source line 319"} {
		if !strings.Contains(got, want) {
			t.Fatalf("source window omitted %q", want)
		}
	}
	if strings.Contains(got, "79: source line 79") || strings.Contains(got, "320: source line 320") {
		t.Fatalf("source window exceeded its bound:\n%s", got)
	}
}
