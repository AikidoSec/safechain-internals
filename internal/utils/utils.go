package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type DownloadVerification struct {
	SafeChainReleaseTag string
	SafeChainAssetName  string
}

type Command struct {
	Command string
	Args    []string
	Env     []string
}

func FetchLatestVersion(ctx context.Context, repoURL, binaryName string) (string, error) {
	latestURL := fmt.Sprintf("%s/releases/latest/download/%s", repoURL, binaryName)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, latestURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusMovedPermanently {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("no redirect location found")
	}

	re := regexp.MustCompile(`/releases/download/([^/]+)/`)
	matches := re.FindStringSubmatch(location)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to extract version from redirect URL: %s", location)
	}

	return matches[1], nil
}

func DetectOS() (string, string) {
	switch runtime.GOOS {
	case "darwin":
		return "macos", ""
	case "windows":
		return "win", ".exe"
	default:
		log.Fatalf("unsupported operating system: %s", runtime.GOOS)
		return "", ""
	}
}

func DetectArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		log.Fatalf("unsupported architecture: %s", runtime.GOARCH)
		return ""
	}
}

func DownloadBinary(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	osName, _ := DetectOS()
	if osName != "win" {
		if err := os.Chown(destPath, os.Getuid(), os.Getgid()); err != nil {
			return fmt.Errorf("failed to set file ownership: %w", err)
		}
	}
	return nil
}

func DownloadAndVerifyBinary(ctx context.Context, url, destPath string, verification DownloadVerification) error {
	releaseTag := strings.TrimSpace(verification.SafeChainReleaseTag)
	assetName := strings.TrimSpace(verification.SafeChainAssetName)
	if releaseTag == "" || assetName == "" {
		return fmt.Errorf("download verification requires release tag and asset name")
	}

	expectedDigest, digestFetched := lookupSafeChainReleaseAssetDigest(ctx, releaseTag, assetName)
	if !digestFetched {
		log.Printf("ERROR: Unable to find digest for asset %q in release %q; skipping verification", assetName, releaseTag)
	}

	if err := DownloadBinary(ctx, url, destPath); err != nil {
		return err
	}

	if digestFetched {
		if err := verifySha256Checksum(destPath, expectedDigest); err != nil {
			_ = os.Remove(destPath)
			return err
		}
	}

	return nil
}

func verifySha256Checksum(filePath, expectedChecksum string) error {
	expectedChecksum = strings.TrimSpace(expectedChecksum)

	// Format matches the CLI: "sha256:<hex>".
	parts := strings.SplitN(expectedChecksum, ":", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "sha256" {
		return fmt.Errorf("unsupported checksum format: %s", expectedChecksum)
	}

	actual, err := ComputeFileSha256Hex(filePath)
	if err != nil {
		return fmt.Errorf("failed to compute sha256: %w", err)
	}

	if strings.ToLower(actual) != strings.ToLower(parts[1]) {
		return fmt.Errorf("checksum verification failed")
	}

	log.Printf("Checksum verification for %s succeeded.", filePath)
	return nil
}

func ComputeFileSha256Hex(filePath string) (string, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func RunCommand(ctx context.Context, command string, args ...string) (string, error) {
	return RunCommandWithEnv(ctx, []string{}, command, args...)
}

func RunCommands(ctx context.Context, commands []Command) ([]string, error) {
	outputs := []string{}
	errs := []error{}
	for _, command := range commands {
		output, err := RunCommandWithEnv(ctx, command.Env, command.Command, command.Args...)
		if err != nil {
			errs = append(errs, err)
		}
		outputs = append(outputs, output)
	}
	if len(errs) > 0 {
		return outputs, fmt.Errorf("failed to run commands")
	}
	return outputs, nil
}

func RunCommandWithEnv(ctx context.Context, env []string, command string, args ...string) (string, error) {
	disableLogging, ok := ctx.Value("disable_logging").(bool)
	if !ok {
		disableLogging = false
	}
	if !disableLogging {
		log.Printf("Running command: %s %s", command, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil && !disableLogging {
		log.Printf("\t- Command error: %v", err)
		log.Printf("\t- Command output: %s", string(output))
	}
	return string(output), err
}

func GetRandomFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to listen on random port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}
