package dependencies

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
)

type browserAPI struct {
	mu       sync.Mutex
	options  adversarylabs.BrowserLoginOptions
	exchange func(context.Context, string, string, string) (adversarylabs.TokenResponse, error)
}

func (c *browserAPI) BeginLogin(context.Context, adversarylabs.LoginOptions) (adversarylabs.DeviceLogin, error) {
	return adversarylabs.DeviceLogin{}, errors.New("unexpected BeginLogin")
}
func (c *browserAPI) LoginWithPassword(context.Context, adversarylabs.PasswordLoginOptions) (adversarylabs.TokenResponse, error) {
	return adversarylabs.TokenResponse{}, errors.New("unexpected LoginWithPassword")
}
func (c *browserAPI) BrowserLoginURL(options adversarylabs.BrowserLoginOptions) (string, error) {
	c.mu.Lock()
	c.options = options
	c.mu.Unlock()
	return "https://login.example.test/authorize", nil
}
func (c *browserAPI) ExchangeCode(ctx context.Context, code, verifier, redirect string) (adversarylabs.TokenResponse, error) {
	if c.exchange == nil {
		return adversarylabs.TokenResponse{}, errors.New("unexpected ExchangeCode")
	}
	return c.exchange(ctx, code, verifier, redirect)
}
func (*browserAPI) PollToken(context.Context, string) (adversarylabs.TokenResponse, error) {
	return adversarylabs.TokenResponse{}, errors.New("unexpected PollToken")
}
func (*browserAPI) Revoke(context.Context, string) error { return errors.New("unexpected Revoke") }
func (*browserAPI) Search(context.Context, string, string) ([]adversarylabs.SearchResult, error) {
	return nil, errors.New("unexpected Search")
}
func (*browserAPI) Whoami(context.Context, string) (adversarylabs.WhoamiResponse, error) {
	return adversarylabs.WhoamiResponse{}, errors.New("unexpected Whoami")
}

func (c *browserAPI) loginOptions() adversarylabs.BrowserLoginOptions {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.options
}

func TestBrowserAuthLoginUsesInjectedLoopbackAndCleansUp(t *testing.T) {
	client := &browserAPI{}
	client.exchange = func(_ context.Context, code, verifier, redirect string) (adversarylabs.TokenResponse, error) {
		if code != "code" || verifier == "" || redirect != client.loginOptions().RedirectURI {
			t.Fatalf("exchange code=%q verifier=%q redirect=%q", code, verifier, redirect)
		}
		return adversarylabs.TokenResponse{Token: "token"}, nil
	}
	var listenedNetwork, listenedAddress string
	var output bytes.Buffer
	auth := BrowserAuth{
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x42}, 104)),
		ListenFunc: func(network, address string) (net.Listener, error) {
			listenedNetwork, listenedAddress = network, address
			return net.Listen(network, address)
		},
		NewServerFunc: NewHTTPCallbackServer,
		OpenFunc: func(context.Context, string) error {
			options := client.loginOptions()
			response, err := http.Get(options.RedirectURI + "?code=code&state=" + options.State)
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return errors.New("callback did not succeed")
			}
			return nil
		},
	}
	token, err := auth.Login(context.Background(), application.BrowserAuthRequest{Client: client, Name: "workstation", Output: &output})
	if err != nil || token.Token != "token" {
		t.Fatalf("token=%#v err=%v", token, err)
	}
	if listenedNetwork != "tcp" || listenedAddress != "127.0.0.1:0" {
		t.Fatalf("listen %q %q", listenedNetwork, listenedAddress)
	}
	options := client.loginOptions()
	if options.State == "" || options.CodeChallenge == "" || options.RedirectURI == "" || options.Name != "workstation" {
		t.Fatalf("options=%#v", options)
	}
	if !strings.Contains(output.String(), "Waiting for browser authentication") {
		t.Fatalf("output=%q", output.String())
	}
}

type callbackServerStub struct {
	serve    func(net.Listener) error
	shutdown func(context.Context) error
}

func (s callbackServerStub) Serve(listener net.Listener) error  { return s.serve(listener) }
func (s callbackServerStub) Shutdown(ctx context.Context) error { return s.shutdown(ctx) }

func TestBrowserAuthInjectedFailuresAreBounded(t *testing.T) {
	validClient := &browserAPI{}
	validClient.exchange = func(context.Context, string, string, string) (adversarylabs.TokenResponse, error) {
		return adversarylabs.TokenResponse{}, nil
	}
	newRequest := func() application.BrowserAuthRequest {
		return application.BrowserAuthRequest{Client: validClient, Output: io.Discard}
	}
	t.Run("entropy", func(t *testing.T) {
		auth := BrowserAuth{Entropy: strings.NewReader("short"), ListenFunc: net.Listen, NewServerFunc: NewHTTPCallbackServer, OpenFunc: func(context.Context, string) error { return nil }}
		if _, err := auth.Login(context.Background(), newRequest()); err == nil || !strings.Contains(err.Error(), "login state") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("listen", func(t *testing.T) {
		auth := BrowserAuth{Entropy: bytes.NewReader(make([]byte, 104)), ListenFunc: func(string, string) (net.Listener, error) { return nil, errors.New("listen failed") }, NewServerFunc: NewHTTPCallbackServer, OpenFunc: func(context.Context, string) error { return nil }}
		if _, err := auth.Login(context.Background(), newRequest()); err == nil || !strings.Contains(err.Error(), "listen failed") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("nil listener", func(t *testing.T) {
		auth := BrowserAuth{Entropy: bytes.NewReader(make([]byte, 104)), ListenFunc: func(string, string) (net.Listener, error) { return nil, nil }, NewServerFunc: NewHTTPCallbackServer, OpenFunc: func(context.Context, string) error { return nil }}
		if _, err := auth.Login(context.Background(), newRequest()); err == nil || !strings.Contains(err.Error(), "listener or address is nil") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("unexpected serve stop", func(t *testing.T) {
		auth := BrowserAuth{Entropy: bytes.NewReader(make([]byte, 104)), ListenFunc: net.Listen, NewServerFunc: func(http.Handler) CallbackServer {
			return callbackServerStub{serve: func(net.Listener) error { return nil }, shutdown: func(context.Context) error { return nil }}
		}, OpenFunc: func(context.Context, string) error { return nil }}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := auth.Login(ctx, newRequest()); err == nil || !strings.Contains(err.Error(), "stopped unexpectedly") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("cancellation shuts down after browser fallback", func(t *testing.T) {
		stopped := make(chan struct{})
		var once sync.Once
		auth := BrowserAuth{Entropy: bytes.NewReader(make([]byte, 104)), ListenFunc: net.Listen, NewServerFunc: func(http.Handler) CallbackServer {
			return callbackServerStub{
				serve: func(net.Listener) error {
					<-stopped
					return http.ErrServerClosed
				},
				shutdown: func(context.Context) error {
					once.Do(func() { close(stopped) })
					return nil
				},
			}
		}, OpenFunc: func(context.Context, string) error { return errors.New("browser unavailable") }}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var output bytes.Buffer
		request := newRequest()
		request.Output = &output
		if _, err := auth.Login(ctx, request); !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
		select {
		case <-stopped:
		default:
			t.Fatal("callback server was not shut down")
		}
		if !strings.Contains(output.String(), "Could not open browser automatically") {
			t.Fatalf("output=%q", output.String())
		}
	})
}

func TestBrowserCallbackRejectsMismatchTokenAndRepeatWithoutBlocking(t *testing.T) {
	results := make(chan browserLoginOutcome, 1)
	calls := 0
	handler := browserCallbackHandler("expected", results, func(code string) (adversarylabs.TokenResponse, error) {
		calls++
		return adversarylabs.TokenResponse{Token: "exchanged"}, nil
	})
	for _, test := range []struct {
		target, method string
		status         int
	}{
		{"/?code=ok&state=wrong", http.MethodGet, http.StatusBadRequest},
		{"/?code=ok&state=expected&token=leaked", http.MethodGet, http.StatusBadRequest},
		{"/?code=ok&state=expected", http.MethodPost, http.StatusMethodNotAllowed},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, test.target, nil))
		if recorder.Code != test.status {
			t.Fatalf("%s: status=%d", test.target, recorder.Code)
		}
	}
	for index := 0; index < 2; index++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?code=ok&state=expected", nil))
		want := http.StatusOK
		if index == 1 {
			want = http.StatusConflict
		}
		if recorder.Code != want {
			t.Fatalf("repeat %d: status=%d", index, recorder.Code)
		}
	}
	if calls != 1 || (<-results).token.Token != "exchanged" {
		t.Fatalf("calls=%d", calls)
	}
}

func TestBrowserCallbackRepeatReturnsWhileExchangeIsBlocked(t *testing.T) {
	results := make(chan browserLoginOutcome, 1)
	started, release := make(chan struct{}), make(chan struct{})
	handler := browserCallbackHandler("expected", results, func(string) (adversarylabs.TokenResponse, error) {
		close(started)
		<-release
		return adversarylabs.TokenResponse{Token: "exchanged"}, nil
	})
	first := make(chan int, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?code=first&state=expected", nil))
		first <- recorder.Code
	}()
	<-started
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/?code=second&state=expected", nil))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("repeat status=%d", recorder.Code)
	}
	close(release)
	if status := <-first; status != http.StatusOK {
		t.Fatalf("first status=%d", status)
	}
	if (<-results).token.Token != "exchanged" {
		t.Fatal("missing exchanged token")
	}
}

func TestBrowserCallbackOAuthErrorCompletesOnce(t *testing.T) {
	results := make(chan browserLoginOutcome, 1)
	handler := browserCallbackHandler("expected", results, func(string) (adversarylabs.TokenResponse, error) {
		t.Fatal("exchange called")
		return adversarylabs.TokenResponse{}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/?error=access_denied&state=expected", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || (<-results).err == nil {
		t.Fatalf("status=%d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("repeat status=%d", recorder.Code)
	}
}
