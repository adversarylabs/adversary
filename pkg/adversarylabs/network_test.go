package adversarylabs

import "testing"

func TestValidateBaseURL(t *testing.T) {
	for _, bad := range []string{"http://api.example", "ftp://api.example", "https://user:pass@api.example", "https://api.example/#fragment", "https:///missing-host"} {
		if _, err := validateBaseURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"https://api.example", "http://localhost:8080", "http://127.0.0.1:8080"} {
		if _, err := validateBaseURL(good); err != nil {
			t.Errorf("rejected %q: %v", good, err)
		}
	}
}

func FuzzValidateBaseURL(f *testing.F) {
	f.Add("https://api.example")
	f.Fuzz(func(t *testing.T, value string) { _, _ = validateBaseURL(value) })
}
