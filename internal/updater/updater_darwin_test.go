//go:build darwin

package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlatformUpdateTo_VerificationGatesInstall(t *testing.T) {
	cases := []struct {
		name          string
		notRoot       bool
		downloadErr   error
		signatureErr  error
		gatekeeperErr error
		contentsErr   error
		installErr    error
		wantOrder     []string
		wantErr       string // substring; "" means no error
		wantPkgKept   bool   // success path leaves the pkg for the detached installer
	}{
		{
			name:        "all verifiers pass; installer runs and pkg is kept",
			wantOrder:   []string{"download", "signature", "gatekeeper", "contents", "install"},
			wantPkgKept: true,
		},
		{
			name:      "non-root errors before any download or verifier",
			notRoot:   true,
			wantOrder: nil,
			wantErr:   "auto-update requires root privileges",
		},
		{
			name:        "download failure stops before any verifier",
			downloadErr: errors.New("net down"),
			wantOrder:   []string{"download"},
			wantErr:     "failed to download",
		},
		{
			name:         "signature failure stops before gatekeeper, contents, install",
			signatureErr: errors.New("bad sig"),
			wantOrder:    []string{"download", "signature"},
			wantErr:      "signature verification failed",
		},
		{
			name:          "gatekeeper failure stops before contents, install",
			gatekeeperErr: errors.New("revoked"),
			wantOrder:     []string{"download", "signature", "gatekeeper"},
			wantErr:       "gatekeeper assessment failed",
		},
		{
			name:        "contents failure stops before install",
			contentsErr: errors.New("version mismatch"),
			wantOrder:   []string{"download", "signature", "gatekeeper", "contents"},
			wantErr:     "contents verification failed",
		},
		{
			name:       "installer failure removes pkg",
			installErr: errors.New("installer failed"),
			wantOrder:  []string{"download", "signature", "gatekeeper", "contents", "install"},
			wantErr:    "failed to start installer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())

			var (
				order   []string
				pkgPath string
			)

			stubAll(t,
				func() bool { return !tc.notRoot },
				func(_ context.Context, _, dest string) error {
					order = append(order, "download")
					pkgPath = dest
					if tc.downloadErr != nil {
						return tc.downloadErr
					}
					return os.WriteFile(dest, []byte("fake pkg"), 0644)
				},
				func(_ context.Context, _ string) error {
					order = append(order, "signature")
					return tc.signatureErr
				},
				func(_ context.Context, _ string) error {
					order = append(order, "gatekeeper")
					return tc.gatekeeperErr
				},
				func(_ context.Context, _, _ string) error {
					order = append(order, "contents")
					return tc.contentsErr
				},
				func(_ string) error {
					order = append(order, "install")
					return tc.installErr
				},
			)

			err := platformUpdateTo(context.Background(), "1.2.3")

			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
			}

			if !equalStrings(order, tc.wantOrder) {
				t.Fatalf("step order mismatch:\n got:  %v\n want: %v", order, tc.wantOrder)
			}

			// The core security invariant: installer was NOT called whenever any
			// verifier returned an error.
			anyVerifierErr := tc.signatureErr != nil || tc.gatekeeperErr != nil || tc.contentsErr != nil
			if anyVerifierErr && contains(order, "install") {
				t.Fatalf("installer was invoked despite a failing verifier; order=%v", order)
			}

			// pkg file lifecycle: kept only on the all-pass success path.
			if pkgPath != "" {
				_, statErr := os.Stat(pkgPath)
				if tc.wantPkgKept && statErr != nil {
					t.Fatalf("expected pkg to remain at %s on success, got stat err: %v", pkgPath, statErr)
				}
				if !tc.wantPkgKept && statErr == nil {
					t.Fatalf("expected pkg at %s to be removed on failure, but it still exists", pkgPath)
				}
			}
		})
	}
}

// TestVerifyPackageSignature exercises the marker-checking against a fake
// pkgutil on PATH; covers each required marker plus the non-zero exit path.
func TestVerifyPackageSignature(t *testing.T) {
	goodOutput := strings.Join([]string{
		expectedStatus,
		"   " + expectedSigner,
		expectedNotarization,
	}, "\n")

	cases := []struct {
		name    string
		stdout  string
		exit    string // empty = exit 0
		wantErr string
	}{
		{name: "all markers present", stdout: goodOutput},
		{
			name:    "missing status marker",
			stdout:  expectedSigner + "\n" + expectedNotarization,
			wantErr: "missing required marker",
		},
		{
			name:    "missing notarization marker",
			stdout:  expectedStatus + "\n" + expectedSigner,
			wantErr: "missing required marker",
		},
		{
			name:    "missing signer marker (wrong team id)",
			stdout:  expectedStatus + "\n" + expectedNotarization + "\n1. Developer ID Installer: Some Other Org (XXXXXXXXXX)",
			wantErr: "missing required marker",
		},
		{
			name:    "pkgutil non-zero exit",
			stdout:  "Error: signature invalid",
			exit:    "1",
			wantErr: "pkgutil --check-signature failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakes(t, map[string]string{"pkgutil": fakePkgUtilScript})
			t.Setenv("FAKE_PKGUTIL_STDOUT", tc.stdout)
			t.Setenv("FAKE_PKGUTIL_EXIT", tc.exit)

			err := verifyPackageSignature(context.Background(), "/dev/null")
			assertErr(t, err, tc.wantErr)
		})
	}
}

// TestVerifyPackageGatekeeper covers spctl marker matching, including the
// case where Apple has revoked notarization (spctl exits non-zero).
func TestVerifyPackageGatekeeper(t *testing.T) {
	goodOutput := strings.Join([]string{
		"/path/to.pkg: " + expectedSpctlAccepted,
		expectedSpctlSource,
		expectedSpctlOrigin,
	}, "\n")

	cases := []struct {
		name    string
		stdout  string
		exit    string
		wantErr string
	}{
		{name: "all markers present", stdout: goodOutput},
		{
			name:    "missing accepted",
			stdout:  expectedSpctlSource + "\n" + expectedSpctlOrigin,
			wantErr: "missing required marker",
		},
		{
			name:    "wrong source (e.g. unsigned)",
			stdout:  expectedSpctlAccepted + "\nsource=Unnotarized Developer ID\n" + expectedSpctlOrigin,
			wantErr: "missing required marker",
		},
		{
			name:    "wrong origin team",
			stdout:  expectedSpctlAccepted + "\n" + expectedSpctlSource + "\norigin=Developer ID Installer: Other (XXXXXXXXXX)",
			wantErr: "missing required marker",
		},
		{
			name:    "spctl non-zero exit (revoked / rejected)",
			stdout:  "rejected",
			exit:    "3",
			wantErr: "spctl assessment failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakes(t, map[string]string{"spctl": fakeSpctlScript})
			t.Setenv("FAKE_SPCTL_STDOUT", tc.stdout)
			t.Setenv("FAKE_SPCTL_EXIT", tc.exit)

			err := verifyPackageGatekeeper(context.Background(), "/dev/null")
			assertErr(t, err, tc.wantErr)
		})
	}
}

// TestVerifyPackageVersion covers the Distribution-file version extraction:
// match, mismatch, alternate <pkg-ref> form, and missing version.
func TestVerifyPackageVersion(t *testing.T) {
	cases := []struct {
		name         string
		distribution string
		expected     string
		expandExit   string
		wantErr      string
	}{
		{
			name:         "product version matches",
			distribution: `<installer-gui-script><product version="1.2.3"/></installer-gui-script>`,
			expected:     "1.2.3",
		},
		{
			name:         "product version matches with v prefix on expected",
			distribution: `<installer-gui-script><product version="1.2.3"/></installer-gui-script>`,
			expected:     "v1.2.3",
		},
		{
			name:         "pkg-ref version used when product version absent",
			distribution: `<installer-gui-script><pkg-ref id="foo" version="1.2.3"/></installer-gui-script>`,
			expected:     "1.2.3",
		},
		{
			name:         "version mismatch is rejected",
			distribution: `<installer-gui-script><product version="9.9.9"/></installer-gui-script>`,
			expected:     "1.2.3",
			wantErr:      "does not match target",
		},
		{
			name:         "missing version in Distribution",
			distribution: `<installer-gui-script></installer-gui-script>`,
			expected:     "1.2.3",
			wantErr:      "version not found in Distribution file",
		},
		{
			name:       "pkgutil --expand non-zero exit",
			expected:   "1.2.3",
			expandExit: "1",
			wantErr:    "pkgutil --expand failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFakes(t, map[string]string{"pkgutil": fakePkgUtilScript})
			t.Setenv("FAKE_DISTRIBUTION", tc.distribution)
			t.Setenv("FAKE_PKGUTIL_EXIT", tc.expandExit)

			err := verifyPackageVersion(context.Background(), "/dev/null", tc.expected)
			assertErr(t, err, tc.wantErr)
		})
	}
}

// stubAll replaces every package-level fn used by platformUpdateTo and
// restores them at test end.
func stubAll(
	t *testing.T,
	root func() bool,
	dl func(context.Context, string, string) error,
	sig, gk func(context.Context, string) error,
	ct func(context.Context, string, string) error,
	inst func(string) error,
) {
	t.Helper()
	origRoot, origDl := runningAsRootFn, downloadBinaryFn
	origSig, origGk := verifyPackageSignatureFn, verifyPackageGatekeeperFn
	origCt, origInst := verifyPackageContentsFn, installPackageDetachedFn
	runningAsRootFn, downloadBinaryFn = root, dl
	verifyPackageSignatureFn, verifyPackageGatekeeperFn = sig, gk
	verifyPackageContentsFn, installPackageDetachedFn = ct, inst
	t.Cleanup(func() {
		runningAsRootFn, downloadBinaryFn = origRoot, origDl
		verifyPackageSignatureFn, verifyPackageGatekeeperFn = origSig, origGk
		verifyPackageContentsFn, installPackageDetachedFn = origCt, origInst
	})
}

// installFakes drops fake executables into a temp dir and prepends it to PATH
// for the duration of the test, so calls to e.g. `pkgutil` resolve to our
// scripts instead of the real binaries.
func installFakes(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func assertErr(t *testing.T, err error, wantSubstr string) {
	t.Helper()
	if wantSubstr == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("expected error containing %q, got %v", wantSubstr, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// fakePkgUtilScript handles the three pkgutil subcommands the updater uses.
// Behavior is driven by env vars set per test:
//   - FAKE_PKGUTIL_STDOUT, FAKE_PKGUTIL_EXIT control --check-signature output
//     and exit code.
//   - FAKE_DISTRIBUTION is written to <expanded>/Distribution on --expand.
//   - FAKE_PKGUTIL_EXIT also gates --expand / --expand-full so we can simulate
//     pkgutil failures in version checks.
const fakePkgUtilScript = `#!/bin/sh
case "$1" in
  --check-signature)
    if [ -n "$FAKE_PKGUTIL_EXIT" ]; then
      printf '%s' "$FAKE_PKGUTIL_STDOUT"
      exit "$FAKE_PKGUTIL_EXIT"
    fi
    printf '%s' "$FAKE_PKGUTIL_STDOUT"
    ;;
  --expand)
    if [ -n "$FAKE_PKGUTIL_EXIT" ]; then exit "$FAKE_PKGUTIL_EXIT"; fi
    mkdir -p "$3"
    if [ -n "$FAKE_DISTRIBUTION" ]; then
      printf '%s' "$FAKE_DISTRIBUTION" > "$3/Distribution"
    fi
    ;;
  --expand-full)
    if [ -n "$FAKE_PKGUTIL_EXIT" ]; then exit "$FAKE_PKGUTIL_EXIT"; fi
    mkdir -p "$3"
    ;;
esac
exit 0
`

const fakeSpctlScript = `#!/bin/sh
if [ -n "$FAKE_SPCTL_EXIT" ]; then
  printf '%s' "$FAKE_SPCTL_STDOUT"
  exit "$FAKE_SPCTL_EXIT"
fi
printf '%s' "$FAKE_SPCTL_STDOUT"
`
