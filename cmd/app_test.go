package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestProcessTTYRejectsRedirectedInputWithoutReadPassword(t *testing.T) {
	var out bytes.Buffer
	secret, err := (processTTY{}).ReadSecret(context.Background(), strings.NewReader("secret"), &out)
	if err == nil || !strings.Contains(err.Error(), "requires a terminal; use --password-stdin") {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	if out.String() != "Password: \n" {
		t.Fatalf("prompt=%q", out.String())
	}
}
