package pip

import "testing"

func TestParsePipVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "standard output",
			input: "pip 23.2.1 from /usr/lib/python3.11/site-packages/pip (python 3.11)",
			want:  "23.2.1",
		},
		{
			name:  "older pip",
			input: "pip 21.0 from /usr/lib/python3.9/site-packages/pip (python 3.9.7)",
			want:  "21.0",
		},
		{
			name:  "pip on python 2",
			input: "pip 20.3.4 from /usr/lib/python2.7/dist-packages/pip (python 2.7)",
			want:  "20.3.4",
		},
		{
			name:  "with trailing whitespace",
			input: "pip 23.0 from /some/path (python 3.12)\n",
			want:  "23.0",
		},
		{
			name:  "with leading whitespace",
			input: "  pip 23.0 from /some/path (python 3.10)  ",
			want:  "23.0",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no pip prefix",
			input:   "something else 23.0",
			wantErr: true,
		},
		{
			name:    "only pip keyword",
			input:   "pip",
			wantErr: true,
		},
		{
			name:    "garbage input",
			input:   "not a pip version string at all",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePipVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
