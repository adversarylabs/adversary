package cmd

import (
	"errors"
	"os"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type concurrentPullResolver struct {
	application.Resolver
	before, winner string
	updateErr      error
	reads, writes  int
}

func (r *concurrentPullResolver) ResolveRecord(string) (repository.Record, error) {
	r.reads++
	digest := r.before
	if r.writes > 0 {
		digest = r.winner
	}
	if digest == "" {
		return repository.Record{}, os.ErrNotExist
	}
	return repository.Record{Digest: digest}, nil
}
func (r *concurrentPullResolver) UpdateRef(string, string, string) error {
	r.writes++
	return r.updateErr
}
func TestRegisterExactRefConcurrentPull(t *testing.T) {
	ioErr := errors.New("write failed")
	for _, tc := range []struct {
		name, before, winner string
		updateErr            error
		wantOK               bool
	}{
		{"create identical", "", "wanted", repository.ErrCAS, true},
		{"retarget identical", "old", "wanted", repository.ErrCAS, true},
		{"create conflicting", "", "other", repository.ErrCAS, false},
		{"retarget conflicting", "old", "other", repository.ErrCAS, false},
		{"winner disappeared", "", "", repository.ErrCAS, false},
		{"unrelated failure", "", "wanted", ioErr, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &concurrentPullResolver{before: tc.before, winner: tc.winner, updateErr: tc.updateErr}
			err := registerExactRef(r, "registry.example/reviewer:1", "wanted")
			if (err == nil) != tc.wantOK {
				t.Fatalf("error=%v", err)
			}
			if !tc.wantOK && !errors.Is(err, tc.updateErr) {
				t.Fatalf("lost cause: %v", err)
			}
			if r.writes != 1 {
				t.Fatalf("wrote %d times; must not overwrite a competing winner", r.writes)
			}
			if tc.updateErr == ioErr && r.reads != 1 {
				t.Fatal("unexpected reread after unrelated failure")
			}
		})
	}
}
