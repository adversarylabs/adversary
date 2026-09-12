package reviewui

import "testing"

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
