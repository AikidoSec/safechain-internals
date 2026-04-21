//go:build darwin

package certconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

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
			got := extractMarkedCertValue(tt.output)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNodeExtraCACertsShellLookups verifies that each shell command in
// nodeCACertsShellLookups correctly reads NODE_EXTRA_CA_CERTS from the
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
			t.Setenv("NODE_EXTRA_CA_CERTS", "")

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

func TestNodeConfiguratorNeedsRepairWhenBundleMissing(t *testing.T) {
	cfg := platform.GetConfig()
	origRunDir, origHomeDir := cfg.RunDir, cfg.HomeDir
	t.Cleanup(func() {
		cfg.RunDir = origRunDir
		cfg.HomeDir = origHomeDir
	})
	cfg.RunDir = t.TempDir()
	cfg.HomeDir = t.TempDir()

	if !newNodeConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when combined CA bundle is missing")
	}
}

func TestNodeConfiguratorNeedsRepairFalseWhenInstalled(t *testing.T) {
	cfg := platform.GetConfig()
	origRunDir, origHomeDir := cfg.RunDir, cfg.HomeDir
	t.Cleanup(func() {
		cfg.RunDir = origRunDir
		cfg.HomeDir = origHomeDir
	})
	cfg.RunDir = t.TempDir()
	cfg.HomeDir = t.TempDir()

	bundlePath := combinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "node-ca")), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := newNodeTrustConfigurator(bundlePath).Install(t.Context()); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	if newNodeConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=false after install")
	}
}

func TestNodeConfiguratorNeedsRepairWhenShellBlockMissing(t *testing.T) {
	cfg := platform.GetConfig()
	origRunDir, origHomeDir := cfg.RunDir, cfg.HomeDir
	t.Cleanup(func() {
		cfg.RunDir = origRunDir
		cfg.HomeDir = origHomeDir
	})
	cfg.RunDir = t.TempDir()
	cfg.HomeDir = t.TempDir()

	bundlePath := combinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "node-shell")), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create .zshrc without the managed block — NeedsRepair must detect the gap.
	if err := os.WriteFile(filepath.Join(cfg.HomeDir, ".zshrc"), []byte("# existing zshrc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newNodeConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when shell config exists but managed block is absent")
	}
}
