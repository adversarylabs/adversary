// Package dependencies contains constructible function adapters for application ports.
// It deliberately provides no package-level defaults or process-global lookups.
package dependencies

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
)

type Clock struct {
	NowFunc   func() time.Time
	TimerFunc func(time.Duration) application.Timer
}

func (c Clock) Now() time.Time {
	if c.NowFunc == nil {
		return time.Time{}
	}
	return c.NowFunc()
}
func (c Clock) NewTimer(d time.Duration) application.Timer {
	if c.TimerFunc == nil {
		return nil
	}
	return c.TimerFunc(d)
}
func (c Clock) Validate() error {
	if c.NowFunc == nil || c.TimerFunc == nil {
		return fmt.Errorf("clock functions required")
	}
	return nil
}

type Environment struct{ LookupFunc func(string) (string, bool) }

func (e Environment) Lookup(key string) (string, bool) {
	if e.LookupFunc == nil {
		return "", false
	}
	return e.LookupFunc(key)
}
func (e Environment) Validate() error {
	if e.LookupFunc == nil {
		return fmt.Errorf("environment lookup function required")
	}
	return nil
}

type HTTPClient struct {
	DoFunc func(*http.Request) (*http.Response, error)
}

func (c HTTPClient) Do(r *http.Request) (*http.Response, error) {
	if c.DoFunc == nil {
		return nil, fmt.Errorf("HTTP function required")
	}
	return c.DoFunc(r)
}
func (c HTTPClient) Validate() error {
	if c.DoFunc == nil {
		return fmt.Errorf("HTTP function required")
	}
	return nil
}

type Browser struct {
	OpenFunc func(context.Context, string) error
}

func (b Browser) Open(ctx context.Context, u string) error {
	if b.OpenFunc == nil {
		return fmt.Errorf("browser function required")
	}
	return b.OpenFunc(ctx, u)
}
func (b Browser) Validate() error {
	if b.OpenFunc == nil {
		return fmt.Errorf("browser function required")
	}
	return nil
}

var _ application.Clock = Clock{}
var _ application.Environment = Environment{}
var _ application.HTTPClient = HTTPClient{}
var _ application.Browser = Browser{}
