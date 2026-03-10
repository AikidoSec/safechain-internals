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
			{
				name:    "chrome-beta",
				dataDir: filepath.Join(appSupport, "Google", "Chrome Beta"),
				bins:    []string{"/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta"},
			},
			{
				name:    "chrome-canary",
				dataDir: filepath.Join(appSupport, "Google", "Chrome Canary"),
				bins:    []string{"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"},
			},
			{
				name:    "chrome-dev",
				dataDir: filepath.Join(appSupport, "Google", "Chrome Dev"),
				bins:    []string{"/Applications/Google Chrome Dev.app/Contents/MacOS/Google Chrome Dev"},
			},
			{
				name:    "brave-nightly",
				dataDir: filepath.Join(appSupport, "BraveSoftware", "Brave-Browser-Nightly"),
				bins:    []string{"/Applications/Brave Browser Nightly.app/Contents/MacOS/Brave Browser Nightly"},
			},
			{
				name:    "dia",
				dataDir: filepath.Join(appSupport, "Dia", "User Data"),
				bins:    []string{"/Applications/Dia.app/Contents/MacOS/Dia"},
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
			{
				name:    "chrome-beta",
				dataDir: filepath.Join(localAppData, "Google", "Chrome Beta", "User Data"),
				bins: []string{
					filepath.Join(programFiles, "Google", "Chrome Beta", "Application", "chrome.exe"),
					filepath.Join(programFilesX86, "Google", "Chrome Beta", "Application", "chrome.exe"),
				},
			},
			{
				name:    "chrome-canary",
				dataDir: filepath.Join(localAppData, "Google", "Chrome SxS", "User Data"),
				bins: []string{
					filepath.Join(programFiles, "Google", "Chrome SxS", "Application", "chrome.exe"),
					filepath.Join(programFilesX86, "Google", "Chrome SxS", "Application", "chrome.exe"),
				},
			},
			{
				name:    "chrome-dev",
				dataDir: filepath.Join(localAppData, "Google", "Chrome Dev", "User Data"),
				bins: []string{
					filepath.Join(programFiles, "Google", "Chrome Dev", "Application", "chrome.exe"),
					filepath.Join(programFilesX86, "Google", "Chrome Dev", "Application", "chrome.exe"),
				},
			},
			{
				name:    "brave-nightly",
				dataDir: filepath.Join(localAppData, "BraveSoftware", "Brave-Browser-Nightly", "User Data"),
				bins: []string{
					filepath.Join(programFiles, "BraveSoftware", "Brave-Browser-Nightly", "Application", "brave.exe"),
				},
			},
		}
	}

	return nil
}

func findInstallations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	browsers := getBrowsers(homeDir)

	var installations []sbom.InstalledVersion

	for _, browser := range browsers {
		profiles := findProfilesWithExtensions(browser.dataDir)
		if len(profiles) == 0 {
			continue
		}

		binaryPath, version := getBrowserBinaryAndVersion(ctx, browser.bins)

		log.Printf("Found %s with %d profile(s) at: %s (binary: %s, version: %s)", browser.name, len(profiles), browser.dataDir, binaryPath, version)
		installations = append(installations, sbom.InstalledVersion{
			Ecosystem: "chrome",
			Variant:   browser.name,
			Version:   version,
			Path:      binaryPath,
			DataPath:  browser.dataDir,
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
