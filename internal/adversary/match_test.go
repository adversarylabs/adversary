package adversary

import "testing"

func TestShouldRunForChangedFiles(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		files    []string
		force    bool
		want     bool
	}{
		{
			name:     "matches recursive workflow glob",
			patterns: []string{".github/workflows/**", "action.yml"},
			files:    []string{".github/workflows/test.yml"},
			want:     true,
		},
		{
			name:     "matches literal file",
			patterns: []string{".github/workflows/**", "action.yml"},
			files:    []string{"action.yml"},
			want:     true,
		},
		{
			name:     "does not match",
			patterns: []string{".github/workflows/**"},
			files:    []string{"README.md"},
			want:     false,
		},
		{
			name:     "force runs",
			patterns: []string{".github/workflows/**"},
			files:    []string{"README.md"},
			force:    true,
			want:     true,
		},
		{
			name:  "no patterns runs",
			files: []string{"README.md"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldRunForChangedFiles(tt.patterns, tt.files, tt.force)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
