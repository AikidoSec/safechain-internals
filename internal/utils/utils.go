package utils

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

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

	return nil
}

func RunCommand(ctx context.Context, command string, args ...string) error {
	log.Printf("Running command: %s %s", command, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
