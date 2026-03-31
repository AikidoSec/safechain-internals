//go:build darwin

package node

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestNodeExtraCACertsShellLookups verifies that each shell command in
// extraCACertsShellLookups correctly reads NODE_EXTRA_CA_CERTS from the
// shell's startup file (both login and interactive variants), and returns
// empty when nothing is set. Tests are skipped if the shell is not installed.
func TestNodeExtraCACertsShellLookups(t *testing.T) {
	const certPath = "/tmp/test-corporate-ca.pem"

	tests := []struct {
		shell      string
		configFile string // relative to HOME
		content    string
	}{
		// Login non-interactive: zsh reads ~/.zprofile
		{
			shell:      "zsh",
			configFile: ".zprofile",
			content:    "export NODE_EXTRA_CA_CERTS=" + certPath + "\n",
		},
		// Interactive non-login: zsh reads ~/.zshrc
		{
			shell:      "zsh",
			configFile: ".zshrc",
			content:    "export NODE_EXTRA_CA_CERTS=" + certPath + "\n",
		},
		// Login non-interactive: bash reads ~/.bash_profile
		{
			shell:      "bash",
			configFile: ".bash_profile",
			content:    "export NODE_EXTRA_CA_CERTS=" + certPath + "\n",
		},
		// Interactive non-login: bash reads ~/.bashrc
		{
			shell:      "bash",
			configFile: ".bashrc",
			content:    "export NODE_EXTRA_CA_CERTS=" + certPath + "\n",
		},
		// fish --login reads ~/.config/fish/config.fish
		{
			shell:      "fish",
			configFile: filepath.Join(".config", "fish", "config.fish"),
			content:    "set -gx NODE_EXTRA_CA_CERTS " + certPath + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.shell+"/"+tt.configFile, func(t *testing.T) {
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

				got, err := runExtraCACertsLookup(context.Background())
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

				got, err := runExtraCACertsLookup(context.Background())
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
