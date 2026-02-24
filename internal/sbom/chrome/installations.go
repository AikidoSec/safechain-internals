package chrome

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type browser struct {
	name    string
	dataDir string
	bins    []string
}

func getBrowsers(homeDir string) []browser {
	switch runtime.GOOS {
	case "darwin":
		appSupport := filepath.Join(homeDir, "Library", "Application Support")
		return []browser{
			{
				name:    "chrome",
				dataDir: filepath.Join(appSupport, "Google", "Chrome"),
				bins:    []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
			},
			{
				name:    "brave",
				dataDir: filepath.Join(appSupport, "BraveSoftware", "Brave-Browser"),
				bins:    []string{"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"},
			},
			{
				name:    "edge",
				dataDir: filepath.Join(appSupport, "Microsoft Edge"),
				bins:    []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"},
			},
			{
				name:    "chromium",
				dataDir: filepath.Join(appSupport, "Chromium"),
				bins:    []string{"/Applications/Chromium.app/Contents/MacOS/Chromium"},
			},
			{
				name:    "arc",
				dataDir: filepath.Join(appSupport, "Arc", "User Data"),
				bins:    []string{"/Applications/Arc.app/Contents/MacOS/Arc"},
			},
		}

	case "linux":
		configDir := filepath.Join(homeDir, ".config")
		return []browser{
			{
				name:    "chrome",
				dataDir: filepath.Join(configDir, "google-chrome"),
				bins:    []string{"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"},
			},
			{
				name:    "brave",
				dataDir: filepath.Join(configDir, "BraveSoftware", "Brave-Browser"),
				bins:    []string{"/usr/bin/brave-browser"},
			},
			{
				name:    "edge",
				dataDir: filepath.Join(configDir, "microsoft-edge"),
				bins:    []string{"/usr/bin/microsoft-edge"},
			},
			{
				name:    "chromium",
				dataDir: filepath.Join(configDir, "chromium"),
				bins:    []string{"/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"},
			},
		}

	case "windows":
		localAppData := filepath.Join(homeDir, "AppData", "Local")
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")
		return []browser{
			{
				name:    "chrome",
				dataDir: filepath.Join(localAppData, "Google", "Chrome", "User Data"),
				bins: []string{
					filepath.Join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
					filepath.Join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
				},
			},
			{
				name:    "brave",
				dataDir: filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
				bins: []string{
					filepath.Join(programFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
				},
			},
			{
				name:    "edge",
				dataDir: filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
				bins: []string{
					filepath.Join(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
					filepath.Join(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
				},
			},
			{
				name:    "chromium",
				dataDir: filepath.Join(localAppData, "Chromium", "User Data"),
			},
		}
	}

	return nil
}

func findInstallations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	browsers := getBrowsers(homeDir)

	var installations []sbom.InstalledVersion

	for _, b := range browsers {
		profiles := findProfilesWithExtensions(b.dataDir)
		if len(profiles) == 0 {
			continue
		}

		binaryPath, version := getBrowserBinaryAndVersion(ctx, b.bins)

		log.Printf("Found %s with %d profile(s) at: %s (binary: %s, version: %s)", b.name, len(profiles), b.dataDir, binaryPath, version)
		installations = append(installations, sbom.InstalledVersion{
			Ecosystem: b.name,
			Version:   version,
			Path:      binaryPath,
			DataPath:  b.dataDir,
		})
	}

	return installations, nil
}

func findProfilesWithExtensions(dataDir string) []string {
	if _, err := os.Stat(dataDir); err != nil {
		return nil
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil
	}

	var profiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name != "Default" && !strings.HasPrefix(name, "Profile ") {
			continue
		}
		extPath := filepath.Join(dataDir, name, "Extensions")
		if _, err := os.Stat(extPath); err == nil {
			profiles = append(profiles, name)
		}
	}

	return profiles
}

func getBrowserBinaryAndVersion(ctx context.Context, bins []string) (binaryPath string, version string) {
	for _, bin := range bins {
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		ver, err := runBrowserVersion(ctx, bin)
		if err != nil {
			continue
		}
		return bin, ver
	}
	return "", ""
}
