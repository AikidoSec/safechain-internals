//go:build darwin

package updater

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io/fs"
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

// Security constants for package verification. Together these pin the publisher
// to Aikido Security and confirm Apple itself vouched for it:
//   - pkgutil --check-signature markers: the package must be signed with a
//     Developer ID issued by Apple (chain validated to a trusted Apple root),
//     notarized by the Apple notary service, and signed by the Aikido Security
//     Apple Developer team (Team ID 7VPF8GD6J4).
//   - spctl (Gatekeeper) markers: the package must be accepted, sourced from a
//     Notarized Developer ID, and originate from Aikido Security's installer cert.
//   - Certificate identity: the xar TOC leaf cert must have O=Aikido Security,
//     OU=7VPF8GD6J4, and CN starting with "Developer ID Installer:".
//   - Codesign requirement: all Mach-O binaries and .app bundles inside the
//     payload must satisfy the designated requirement pinning subject.OU to our
//     team ID.
//
// We deliberately do not pin specific cert fingerprints (leaf, intermediate,
// or root): all three rotate over time and pinning them would brick legitimate
// updates after a rotation.
const (
	expectedStatus       = "Status: signed by a developer certificate issued by Apple for distribution"
	expectedNotarization = "Notarization: trusted by the Apple notary service"
	expectedSigner       = "1. Developer ID Installer: Aikido Security (7VPF8GD6J4)"

	expectedSpctlAccepted = "accepted"
	expectedSpctlSource   = "source=Notarized Developer ID"
	expectedSpctlOrigin   = "origin=Developer ID Installer: Aikido Security (7VPF8GD6J4)"

	aikidoOrganization  = "Aikido Security"
	aikidoTeamID        = "7VPF8GD6J4"
	installerCNPrefix   = "Developer ID Installer:"
	codesignRequirement = `anchor apple generic and certificate leaf[subject.OU] = "7VPF8GD6J4"`
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

	if err = verifyPackageGatekeeper(ctx, pkgPath); err != nil {
		return fmt.Errorf("gatekeeper assessment failed: %w", err)
	}

	if err = verifyPackageContents(ctx, pkgPath, version); err != nil {
		return fmt.Errorf("contents verification failed: %w", err)
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

// verifyPackageGatekeeper runs Apple's Gatekeeper assessment on the package via
// `spctl -a -vvv -t install`. This is a stronger check than `pkgutil
// --check-signature` alone: spctl evaluates the file against the live
// Gatekeeper policy (Notarized Developer ID) and confirms Apple has not
// revoked the developer/notarization ticket.
func verifyPackageGatekeeper(ctx context.Context, pkgPath string) error {
	out, err := exec.CommandContext(ctx, "spctl", "-a", "-vvv", "-t", "install", pkgPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("spctl assessment failed: %v: %s", err, string(out))
	}
	output := string(out)

	for _, marker := range []string{expectedSpctlAccepted, expectedSpctlSource, expectedSpctlOrigin} {
		if !strings.Contains(output, marker) {
			return fmt.Errorf("gatekeeper assessment missing required marker %q:\n%s", marker, output)
		}
	}

	log.Printf("Package gatekeeper assessment passed (%s)", expectedSpctlOrigin)
	return nil
}

func verifyPackageContents(ctx context.Context, pkgPath, expectedVersion string) error {
	if err := verifyPackageVersion(ctx, pkgPath, expectedVersion); err != nil {
		return err
	}
	if err := verifyPackageCertificate(ctx, pkgPath); err != nil {
		return err
	}
	if err := verifyPayloadCodesign(ctx, pkgPath); err != nil {
		return err
	}
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

type xarTOC struct {
	XMLName xml.Name    `xml:"xar"`
	TOC     xarTOCInner `xml:"toc"`
}

type xarTOCInner struct {
	Signatures  []xarSignature `xml:"signature"`
	XSignatures []xarSignature `xml:"x-signature"`
}

type xarSignature struct {
	KeyInfo xarKeyInfo `xml:"KeyInfo"`
}

type xarKeyInfo struct {
	X509Data []xarX509Data `xml:"X509Data"`
}

type xarX509Data struct {
	Certificates []string `xml:"X509Certificate"`
}

func verifyPackageCertificate(ctx context.Context, pkgPath string) error {
	tocDir, err := os.MkdirTemp("", "aikido-pkg-toc-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tocDir)

	tocPath := filepath.Join(tocDir, "toc.xml")
	if out, err := exec.CommandContext(ctx, "xar", "--dump-toc="+tocPath, "-f", pkgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("xar --dump-toc failed: %v: %s", err, string(out))
	}

	tocData, err := os.ReadFile(tocPath)
	if err != nil {
		return fmt.Errorf("failed to read xar TOC: %w", err)
	}

	var toc xarTOC
	if err := xml.Unmarshal(tocData, &toc); err != nil {
		return fmt.Errorf("failed to parse xar TOC XML: %w", err)
	}

	var certs []*x509.Certificate
	allSigs := append(toc.TOC.Signatures, toc.TOC.XSignatures...)
	for _, sig := range allSigs {
		for _, x509data := range sig.KeyInfo.X509Data {
			for _, raw := range x509data.Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(raw), ""))
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				certs = append(certs, cert)
			}
		}
	}

	if len(certs) == 0 {
		return fmt.Errorf("no X.509 certificates found in xar TOC")
	}

	var leaf *x509.Certificate
	for _, c := range certs {
		if strings.HasPrefix(c.Subject.CommonName, installerCNPrefix) {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return fmt.Errorf("no leaf certificate with CN prefix %q found in xar TOC", installerCNPrefix)
	}

	hasOrg := false
	for _, o := range leaf.Subject.Organization {
		if o == aikidoOrganization {
			hasOrg = true
			break
		}
	}
	if !hasOrg {
		return fmt.Errorf("leaf certificate Organization does not contain %q: %v", aikidoOrganization, leaf.Subject.Organization)
	}

	hasOU := false
	for _, ou := range leaf.Subject.OrganizationalUnit {
		if ou == aikidoTeamID {
			hasOU = true
			break
		}
	}
	if !hasOU {
		return fmt.Errorf("leaf certificate OrganizationalUnit does not contain %q: %v", aikidoTeamID, leaf.Subject.OrganizationalUnit)
	}

	expectedTeamInCN := "(" + aikidoTeamID + ")"
	if !strings.Contains(leaf.Subject.CommonName, expectedTeamInCN) {
		return fmt.Errorf("leaf certificate CN %q does not contain %q", leaf.Subject.CommonName, expectedTeamInCN)
	}

	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("leaf certificate not valid at current time (notBefore=%s, notAfter=%s)", leaf.NotBefore, leaf.NotAfter)
	}

	fingerprint := sha256.Sum256(leaf.Raw)
	log.Printf("Package signing certificate verified (CN=%s, serial=%s, SHA-256=%x, expires=%s)",
		leaf.Subject.CommonName, leaf.SerialNumber, fingerprint, leaf.NotAfter.Format(time.DateOnly))
	return nil
}

func isMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return false
	}

	switch magic {
	case 0xfeedface, 0xfeedfacf, // Mach-O 32/64
		0xcefaedfe, 0xcffaedfe, // Mach-O 32/64 byte-swapped
		0xbebafeca, 0xcafebabe: // Fat binary (universal)
		return true
	}
	return false
}

func verifyPayloadCodesign(ctx context.Context, pkgPath string) error {
	extractDir, err := os.MkdirTemp("", "aikido-pkg-expand-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	expanded := filepath.Join(extractDir, "pkg")
	out, err := exec.CommandContext(ctx, "pkgutil", "--expand-full", pkgPath, expanded).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pkgutil --expand-full failed: %v: %s", err, string(out))
	}

	reqFlag := "-R=" + codesignRequirement
	var machoCount, bundleCount int
	var verifyErrors []string

	err = filepath.WalkDir(expanded, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && strings.HasSuffix(d.Name(), ".app") {
			bundleCount++

			out, err := exec.CommandContext(ctx, "codesign", "--verify", "--strict", "--deep", reqFlag, path).CombinedOutput()
			if err != nil {
				verifyErrors = append(verifyErrors, fmt.Sprintf("%s: %v: %s", path, err, string(out)))
			} else {
				log.Printf("App bundle code sign verified: %s", path)
			}
			return fs.SkipDir
		}

		if !d.Type().IsRegular() {
			return nil
		}

		if isMachO(path) {
			machoCount++
			out, err := exec.CommandContext(ctx, "codesign", "--verify", "--strict", reqFlag, path).CombinedOutput()
			if err != nil {
				verifyErrors = append(verifyErrors, fmt.Sprintf("%s: %v: %s", path, err, string(out)))
			} else {
				log.Printf("Mach-O binary code sign verified: %s", path)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk expanded package: %w", err)
	}

	if machoCount+bundleCount == 0 {
		return fmt.Errorf("no signed Mach-O binaries or app bundles found in pkg payload")
	}

	if len(verifyErrors) > 0 {
		return fmt.Errorf("codesign verification failed for %d item(s):\n%s", len(verifyErrors), strings.Join(verifyErrors, "\n"))
	}

	log.Printf("Package payload codesign verified (mach-o=%d, bundles=%d)", machoCount, bundleCount)
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

	cmd := exec.Command("/usr/sbin/installer", "-verbose", "-pkg", pkgPath, "-target", "/")
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
