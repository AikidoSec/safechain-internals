//go:build darwin

package updater

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

// Markers we require in the `pkgutil --check-signature` output. Together these
// pin the publisher to Aikido Security and confirm Apple itself vouched for it:
//   - the package must be signed with a Developer ID issued by Apple (this also
//     means pkgutil successfully validated the chain to a trusted Apple root),
//   - notarized by the Apple notary service,
//   - signed by the Aikido Security Apple Developer team (Team ID 7VPF8GD6J4).
//
// We deliberately do not pin specific cert fingerprints (leaf, intermediate,
// or root): all three rotate over time and pinning them would brick legitimate
// updates after a rotation.
const (
	expectedStatus       = "Status: signed by a developer certificate issued by Apple for distribution"
	expectedNotarization = "Notarization: trusted by the Apple notary service"
	expectedSigner       = "Developer ID Installer: Aikido Security (7VPF8GD6J4)"
)

var (
	productVersionRegex = regexp.MustCompile(`<product\b[^>]*\bversion="([^"]+)"`)
	pkgRefVersionRegex  = regexp.MustCompile(`<pkg-ref\b[^>]*\bversion="([^"]+)"`)
)

func platformUpdateTo(ctx context.Context, version string) (err error) {
	if !platform.RunningAsRoot() {
		return fmt.Errorf("auto-update requires root privileges")
	}

	tag := releaseTag(version)
	url := fmt.Sprintf("%s/download/%s/%s", releasesBaseURL, tag, pkgAssetName)

	timestamp := time.Now().UTC().Format("20060102T150405")
	pkgPath := filepath.Join(os.TempDir(), fmt.Sprintf("AikidoSecurity-EndpointProtection-Update-%s-%s.pkg", version, timestamp))
	// On any failure path we clean up the pkg file. On success we leave it in
	// place because the detached installer process still needs it.
	defer func() {
		if err != nil {
			_ = os.Remove(pkgPath)
		}
	}()

	log.Printf("Downloading %s from %s", pkgAssetName, url)
	if err = utils.DownloadBinary(ctx, url, pkgPath); err != nil {
		return fmt.Errorf("failed to download %s: %w", pkgAssetName, err)
	}

	if err = verifyPackageSignature(ctx, pkgPath); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	if err = verifyPackageVersion(ctx, pkgPath, version); err != nil {
		return fmt.Errorf("version verification failed: %w", err)
	}

	if err = installPackageDetached(pkgPath); err != nil {
		return fmt.Errorf("failed to start installer: %w", err)
	}

	log.Printf("Installer started for version %s; daemon will exit when the package replaces it", version)
	return nil
}

func verifyPackageSignature(ctx context.Context, pkgPath string) error {
	out, err := exec.CommandContext(ctx, "pkgutil", "--check-signature", pkgPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pkgutil --check-signature failed: %v: %s", err, string(out))
	}
	output := string(out)

	for _, marker := range []string{expectedStatus, expectedNotarization, expectedSigner} {
		if !strings.Contains(output, marker) {
			return fmt.Errorf("package signature missing required marker %q:\n%s", marker, output)
		}
	}

	log.Printf("Package signature verified (signer: %s)", expectedSigner)
	return nil
}

func verifyPackageVersion(ctx context.Context, pkgPath, expected string) error {
	extractDir, err := os.MkdirTemp("", "aikido-pkg-version-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	cmd := exec.CommandContext(ctx, "xar", "-xf", pkgPath, "Distribution")
	cmd.Dir = extractDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to extract Distribution from pkg: %v: %s", err, string(out))
	}

	data, err := os.ReadFile(filepath.Join(extractDir, "Distribution"))
	if err != nil {
		return fmt.Errorf("failed to read Distribution file: %w", err)
	}

	actual := ""
	if m := productVersionRegex.FindStringSubmatch(string(data)); m != nil {
		actual = m[1]
	} else if m := pkgRefVersionRegex.FindStringSubmatch(string(data)); m != nil {
		actual = m[1]
	}
	if actual == "" {
		return fmt.Errorf("version not found in Distribution file")
	}

	if normalizeVersion(actual) != normalizeVersion(expected) {
		return fmt.Errorf("package version %q does not match target %q", actual, expected)
	}
	log.Printf("Package version %s matches target", actual)
	return nil
}

// updateLogName is the file (under platform.GetLogDir()) where installer
// stdout/stderr is appended across all auto-update attempts.
const updateLogName = "endpoint-protection-update.log"

// installPackageDetached starts `installer` in a brand-new session so that it
// keeps running after the package's pre-install scripts terminate this daemon.
// Setsid moves the new process out of our process group/session, and Release
// hands off bookkeeping so launchd/init reaps it instead of us.
//
// Installer output is appended to a dedicated update log so we can inspect
// failed installs after the fact (the daemon itself is dead by then).
func installPackageDetached(pkgPath string) error {
	log.Printf("Starting detached installer for %s", pkgPath)

	logPath := filepath.Join(platform.GetLogDir(), updateLogName)
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open update log %s: %v; installer output will be discarded", logPath, err)
		logFile = nil
	} else {
		defer logFile.Close()
		fmt.Fprintf(logFile, "\n=== %s installer starting for %s ===\n\n", time.Now().UTC().Format(time.RFC3339), pkgPath)
	}

	cmd := exec.Command("/usr/sbin/installer", "-pkg", pkgPath, "-target", "/")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	log.Printf("Installer started (PID %d); output appended to %s", cmd.Process.Pid, logPath)
	return cmd.Process.Release()
}
