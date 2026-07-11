package dependencies

import (
	"context"
	"testing"
)

func TestNilFunctionAdaptersAreSafeAndInvalid(t *testing.T) {
	if (Clock{}).Validate() == nil || (Environment{}).Validate() == nil || (HTTPClient{}).Validate() == nil || (Browser{}).Validate() == nil {
		t.Fatal("nil adapter validated")
	}
	_ = (Clock{}).Now()
	if got, ok := (Environment{}).Lookup("x"); got != "" || ok {
		t.Fatal("nil environment lookup")
	}
	if _, err := (HTTPClient{}).Do(nil); err == nil {
		t.Fatal("nil HTTP adapter did not error")
	}
	if err := (Browser{}).Open(context.Background(), "https://example.test"); err == nil {
		t.Fatal("nil browser adapter did not error")
	}
}
