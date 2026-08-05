package workspace

import "testing"

func TestPreferLocalWhenBothInScope(t *testing.T) {
	cfg := Config{}
	id, role := PreferLocalOwner(cfg, "acme-db", "go-database", true, true)
	if id != "acme-db" || role != RoleLocalTrainable {
		t.Fatalf("prefer local: got %s %s", id, role)
	}
}

func TestPreferOfficialWhenOnlyOfficialInScope(t *testing.T) {
	en := true
	cfg := Config{Official: OfficialConfig{Enabled: &en}}
	id, role := PreferLocalOwner(cfg, "", "go-testing", false, true)
	if id != "go-testing" || role != RoleOfficialJury {
		t.Fatalf("got %s %s", id, role)
	}
}
