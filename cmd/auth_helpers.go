package cmd

import (
	"context"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"io"
	"strings"
	"time"
)

func waitForLogin(ctx context.Context, clock application.Clock, client application.APIClient, login adversarylabs.DeviceLogin) (adversarylabs.TokenResponse, error) {
	interval := adversarylabs.PollInterval(login)
	expiresAt := clock.Now().Add(time.Duration(login.ExpiresIn) * time.Second)
	if login.ExpiresIn <= 0 {
		expiresAt = clock.Now().Add(10 * time.Minute)
	}
	pollCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	for {
		if err := pollCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		token, err := client.PollToken(pollCtx, login.DeviceCode)
		if err == nil {
			return token, nil
		}
		if pollCtx.Err() != nil {
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		timer := clock.NewTimer(interval)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		case <-timer.C():
		}
	}
}

func loginWithDevice(ctx context.Context, clock application.Clock, stdout io.Writer, client application.APIClient, opts *loginOptions) (adversarylabs.TokenResponse, error) {
	login, err := client.BeginLogin(ctx, adversarylabs.LoginOptions{Name: opts.name, CI: opts.ci})
	if err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	verificationURL := login.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = login.VerificationURI
	}
	if verificationURL == "" || login.UserCode == "" {
		return adversarylabs.TokenResponse{}, fmt.Errorf("device login response was missing verification instructions")
	}
	fmt.Fprintf(stdout, "Open %s\n\nEnter code: %s\n\nWaiting for authentication...\n", verificationURL, login.UserCode)
	return waitForLogin(ctx, clock, client, login)
}

func readPasswordLine(r io.Reader) (string, error) {
	return readSecretLine(r, "password")
}

func readSecretLine(r io.Reader, kind string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil {
		return "", err
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("%s from standard input is empty", kind)
	}
	return secret, nil
}
