//go:build darwin

package certconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNodeExtraCACertsShellLookups verifies that each shell command in
// nodeCACertsShellLookups correctly reads NODE_EXTRA_CA_CERTS when it is set
// in the shell's login startup file, and returns empty when it is not set.
//
// These are integration tests — they spawn real shells and require zsh, bash,
// or fish to be available on the machine. Each sub-test is skipped individually
// if the shell is not found.
func TestNodeExtraCACertsShellLookups(t *testing.T) {
	const certPath = "/tmp/test-corporate-ca.pem"

	tests := []struct {
		shell      string
		configFile string // relative to HOME
		content    string
	}{
		{
			shell:      "zsh",
			configFile: ".zprofile",
			content:    "export NODE_EXTRA_CA_CERTS=" + certPath + "\n",
		},
		{
			shell:      "bash",
			configFile: ".bash_profile",
			content:    "export NODE_EXTRA_CA_CERTS=" + certPath + "\n",
		},
		{
			shell:      "fish",
			configFile: filepath.Join(".config", "fish", "config.fish"),
			content:    "set -gx NODE_EXTRA_CA_CERTS " + certPath + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.shell, func(t *testing.T) {
			if _, err := exec.LookPath(tt.shell); err != nil {
				t.Skipf("%s not available: %v", tt.shell, err)
			}

			home := t.TempDir()
			t.Setenv("HOME", home)

			configPath := filepath.Join(home, tt.configFile)
			if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
				t.Fatal(err)
			}

			t.Run("value set", func(t *testing.T) {
				if err := os.WriteFile(configPath, []byte(tt.content), 0o644); err != nil {
					t.Fatal(err)
				}

				got, err := runNodeExtraCACertsLookup(context.Background())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != certPath {
					t.Fatalf("got %q, want %q", got, certPath)
				}
			})

			t.Run("not set", func(t *testing.T) {
				if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}

				got, err := runNodeExtraCACertsLookup(context.Background())
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != "" {
					t.Fatalf("got %q, want empty string", got)
				}
			})
		})
	}
}
