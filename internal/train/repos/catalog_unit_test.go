package repos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoHelpersAndFilter(t *testing.T) {
	r := Repo{Owner: "o", Name: "n", Languages: []string{"go"}, Role: "discovery"}
	if r.FullName() != "o/n" {
		t.Fatal(r.FullName())
	}
	if !r.IsEnabled() {
		t.Fatal()
	}
	f := false
	r.Enabled = &f
	if r.IsEnabled() {
		t.Fatal()
	}
	r.Enabled = nil
	if !r.MatchesLanguages(nil) || !r.MatchesLanguages([]string{"any"}) {
		t.Fatal()
	}
	if !r.MatchesLanguages([]string{"go"}) {
		t.Fatal()
	}
	if r.MatchesLanguages([]string{"python"}) {
		t.Fatal()
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "repositories.json")
	body := `{"schema_version":1,"repositories":[
	  {"owner":"a","name":"one","languages":["go"],"role":"discovery"},
	  {"owner":"b","name":"two","languages":["python"],"role":"validation"},
	  {"owner":"","name":"bad","languages":["go"]}
	]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d := c.Filter("discovery", []string{"go"})
	if len(d) != 1 || d[0].Name != "one" {
		t.Fatalf("%+v", d)
	}
	if DefaultPath("/x") != filepath.Join("/x", "config", "repositories.json") {
		t.Fatal(DefaultPath("/x"))
	}
}
