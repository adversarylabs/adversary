package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
)

func TestExitCodeContract(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 0},
		{"findings", &internaladversary.FindingsError{Count: 2}, 1},
		{"usage", &application.Error{Operation: "parse", Kind: "usage", Err: errors.New("bad flag")}, 2},
		{"protocol", &internaladversary.ProtocolError{Err: errors.New("invalid envelope")}, 3},
		{"network", &application.Error{Operation: "pull", Kind: "network", Err: errors.New("offline")}, 4},
		{"interrupt", context.Canceled, 130},
		{"timeout", context.DeadlineExceeded, 3},
		{"network deadline", &application.Error{Operation: "pull", Kind: "network", Err: context.DeadlineExceeded}, 4},
		{"auth deadline", &application.Error{Operation: "login", Kind: "auth", Err: context.DeadlineExceeded}, 4},
		{"network cancellation", &application.Error{Operation: "pull", Kind: "network", Err: context.Canceled}, 130},
		{"child", &internaladversary.ChildExitError{ExitCode: 42, Err: errors.New("exit")}, 3},
		{"misleading protocol text", errors.New("network authentication protocol unauthorized"), 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.err); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCobraArgumentAndFlagFailuresAreTypedUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"arguments": {"version", "extra"},
		"flag":      {"version", "--definitely-not-a-flag"},
	} {
		t.Run(name, func(t *testing.T) {
			command := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
			command.SetArgs(args)
			err := command.Execute()
			if !application.IsKind(err, "usage") || ExitCode(err) != 2 {
				t.Fatalf("error = %#v, code = %d", err, ExitCode(err))
			}
		})
	}
}
