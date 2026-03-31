package shared

import "testing"

func TestExtractMarkedCertValue(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"clean output", "AIKIDO_CERT=/path/to/ca.pem\n", "/path/to/ca.pem"},
		{"empty value", "AIKIDO_CERT=\n", ""},
		{"marker absent", "some random output\n", ""},
		{"marker buried in noise", "Welcome to zsh!\nAIKIDO_CERT=/corp/ca.pem\nsome trailing line", "/corp/ca.pem"},
		{"interactive startup noise before", "compinit output\n[oh-my-zsh]\nAIKIDO_CERT=/ca.pem\n", "/ca.pem"},
		{"whitespace trimmed", "AIKIDO_CERT=  /ca.pem  \n", "/ca.pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractMarkedCertValue(tt.output)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
