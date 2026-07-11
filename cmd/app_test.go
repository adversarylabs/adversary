package cmd

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/adversarylabs"
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

func TestProcessAPIFactoryUsesHardenedProductionClient(t *testing.T) {
	got := (processAPIFactory{store: adversarylabs.ConfigStore{Path: "/config"}}).New("https://api.example")
	classified, ok := got.(classifiedAPIClient)
	if !ok {
		t.Fatalf("client = %T, want classifiedAPIClient", got)
	}
	client, ok := classified.inner.(adversarylabs.Client)
	if !ok {
		t.Fatalf("inner = %T, want adversarylabs.Client", classified.inner)
	}
	if client.HTTP == nil || client.HTTP == http.DefaultClient || client.HTTP.Timeout != 2*time.Minute {
		t.Fatalf("HTTP=%p default=%p timeout=%s", client.HTTP, http.DefaultClient, client.HTTP.Timeout)
	}
	if client.HTTP.Transport == nil || client.HTTP.Transport == http.DefaultTransport {
		t.Fatalf("transport = %T, want dedicated hardened transport", client.HTTP.Transport)
	}
}

func TestProcessAPIFactoryRetainsExplicitTestInjection(t *testing.T) {
	injected := &http.Client{Timeout: time.Second}
	got := (processAPIFactory{store: adversarylabs.ConfigStore{Path: "/config"}, http: injected}).New("https://api.example")
	client := got.(classifiedAPIClient).inner.(adversarylabs.Client)
	if client.HTTP != injected {
		t.Fatalf("HTTP=%p, want injected %p", client.HTTP, injected)
	}
}
