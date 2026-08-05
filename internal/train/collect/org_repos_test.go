package collect

import (
	"testing"
)

func TestParseOrgReposJSON(t *testing.T) {
	raw := []byte(`[
  {"name":"payments","full_name":"acme/payments","archived":false,"owner":{"login":"acme"}},
  {"name":"old","full_name":"acme/old","archived":true,"owner":{"login":"acme"}},
  {"name":"ledger","full_name":"acme/ledger","archived":false,"owner":{"login":"acme"}}
]`)
	got, err := parseOrgReposJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d repos: %#v", len(got), got)
	}
	if got[0].FullName() != "acme/payments" || got[1].FullName() != "acme/ledger" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseOrgReposJSONPaginated(t *testing.T) {
	// gh --paginate concatenates arrays.
	raw := []byte(`[{"name":"a","full_name":"o/a","archived":false,"owner":{"login":"o"}}][{"name":"b","full_name":"o/b","archived":false,"owner":{"login":"o"}}]`)
	got, err := parseOrgReposJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d: %#v", len(got), got)
	}
}

func TestFilterOrgReposAllowlist(t *testing.T) {
	in := []OrgRepo{
		{Owner: "acme", Name: "payments"},
		{Owner: "acme", Name: "ledger"},
		{Owner: "acme", Name: "website"},
	}
	got := filterOrgRepos(in, []string{"Payments", "acme/ledger"})
	if len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
	if got[0].Name != "payments" || got[1].Name != "ledger" {
		t.Fatalf("got %#v", got)
	}
}

func TestFilterOrgReposEmptyAllowlist(t *testing.T) {
	in := []OrgRepo{{Owner: "a", Name: "b"}}
	got := filterOrgRepos(in, nil)
	if len(got) != 1 {
		t.Fatalf("got %#v", got)
	}
}
