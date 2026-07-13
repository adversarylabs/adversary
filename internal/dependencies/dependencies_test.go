package dependencies

import (
	"context"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
)

func TestNilFunctionAdaptersAreSafeAndInvalid(t *testing.T) {
	if (Clock{}).Validate() == nil || (Environment{}).Validate() == nil || (HTTPClient{}).Validate() == nil || (BrowserAuth{}).Validate() == nil {
		t.Fatal("nil adapter validated")
	}
	_ = (Clock{}).Now()
	if got, ok := (Environment{}).Lookup("x"); got != "" || ok {
		t.Fatal("nil environment lookup")
	}
	if _, err := (HTTPClient{}).Do(nil); err == nil {
		t.Fatal("nil HTTP adapter did not error")
	}
	if _, err := (BrowserAuth{}).Login(context.Background(), application.BrowserAuthRequest{}); err == nil {
		t.Fatal("nil browser auth adapter did not error")
	}
}
