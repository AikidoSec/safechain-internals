package configure_maven

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	javaCertAlias           = "safechain-proxy"
	javaTruststorePassword  = "changeit"
)

type javaInstall struct {
	javaHome string
	cacerts  string
	keytool  string
}

func installJavaCA(ctx context.Context, certPath string) error {
	installs, err := findJavaInstalls(ctx)
	if err != nil {
		return err
	}
	if len(installs) == 0 {
		return fmt.Errorf("no Java installations found")
	}

	log.Printf("Found %d Java installation(s) for certificate installation", len(installs))
	var errs []string
	var successCount int
	for _, install := range installs {
		log.Printf("Processing Java home: %s", install.javaHome)
		if err := ensureKeytoolAvailable(install.keytool); err != nil {
			log.Printf("  Skipping (keytool unavailable): %v", err)
			errs = append(errs, fmt.Sprintf("%s: %v", install.cacerts, err))
			continue
		}
		if aliasExists(ctx, install.keytool, install.cacerts) {
			log.Printf("  Certificate already installed at %s", install.cacerts)
			successCount++
			continue
		}
		if err := runKeytool(ctx, install.keytool, []string{
			"-importcert",
			"-file", certPath,
			"-alias", javaCertAlias,
			"-keystore", install.cacerts,
			"-storepass", javaTruststorePassword,
			"-noprompt",
		}); err != nil {
			log.Printf("  Failed to install at %s: %v", install.cacerts, err)
			errs = append(errs, fmt.Sprintf("%s: %v", install.cacerts, err))
		} else {
			log.Printf("  Successfully installed certificate at %s", install.cacerts)
			successCount++
		}
	}

	log.Printf("Certificate installation complete: %d succeeded, %d failed", successCount, len(errs))
	if len(errs) > 0 {
		return fmt.Errorf("failed to install proxy CA to some Java truststores: %s", strings.Join(errs, "; "))
	}

	return nil
}

func uninstallJavaCA(ctx context.Context) error {
	installs, err := findJavaInstalls(ctx)
	if err != nil {
		return err
	}
	if len(installs) == 0 {
		return nil
	}

	var errs []string
	for _, install := range installs {
		if err := ensureKeytoolAvailable(install.keytool); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", install.cacerts, err))
			continue
		}
		if !aliasExists(ctx, install.keytool, install.cacerts) {
			continue
		}
		if err := runKeytool(ctx, install.keytool, []string{
			"-delete",
			"-alias", javaCertAlias,
			"-keystore", install.cacerts,
			"-storepass", javaTruststorePassword,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", install.cacerts, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to remove proxy CA from some Java truststores: %s", strings.Join(errs, "; "))
	}

	return nil
}

func findJavaInstalls(ctx context.Context) ([]javaInstall, error) {
	javaHomes, err := findJavaHomes(ctx)
	if err != nil {
		return nil, err
	}

	keytoolDefault, _ := exec.LookPath(keytoolBinaryName())
	seen := make(map[string]bool)
	var installs []javaInstall
	for _, javaHome := range javaHomes {
		for _, cacertsPath := range candidateCacertsPaths(javaHome) {
			if seen[cacertsPath] {
				continue
			}
			if _, err := os.Stat(cacertsPath); err != nil {
				continue
			}
			keytoolPath := keytoolDefault
			if keytoolPath == "" {
				keytoolPath = filepath.Join(javaHome, "bin", keytoolBinaryName())
			}
			seen[cacertsPath] = true
			installs = append(installs, javaInstall{
				javaHome: javaHome,
				cacerts:  cacertsPath,
				keytool:  keytoolPath,
			})
		}
	}

	return installs, nil
}

func findJavaHomes(ctx context.Context) ([]string, error) {
	seen := make(map[string]bool)
	var homes []string

	if javaHome := strings.TrimSpace(os.Getenv("JAVA_HOME")); javaHome != "" {
		if addUniqueHome(&homes, seen, javaHome) {
			return homes, nil
		}
	}

	switch runtime.GOOS {
	case "darwin":
		return append(homes, findJavaHomesDarwin(ctx, seen)...), nil
	case "windows":
		return append(homes, findJavaHomesWindows(seen)...), nil
	case "linux":
		return append(homes, findJavaHomesLinux(seen)...), nil
	default:
		return homes, nil
	}
}

func findJavaHomesDarwin(ctx context.Context, seen map[string]bool) []string {
	var homes []string
	
	// Method 1: Use /usr/libexec/java_home -V to list all registered JDKs
	output, err := exec.CommandContext(ctx, "/usr/libexec/java_home", "-V").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "/") {
				addUniqueHome(&homes, seen, line)
			}
		}
	}
	
	// Method 2: Get default Java home
	if output, err := exec.CommandContext(ctx, "/usr/libexec/java_home").Output(); err == nil {
		addUniqueHome(&homes, seen, strings.TrimSpace(string(output)))
	}
	
	// Method 3: Resolve java executable from PATH (catches Homebrew installs)
	if javaPath, err := exec.LookPath("java"); err == nil {
		if resolved, err := filepath.EvalSymlinks(javaPath); err == nil {
			// For macOS, Java home is typically two directories up from bin/java
			javaHome := filepath.Dir(filepath.Dir(resolved))
			// If it's inside a .jdk bundle, navigate to Contents/Home
			if strings.Contains(javaHome, ".jdk") {
				// Check if we're at /path/to/something.jdk/Contents/Home/bin
				if strings.HasSuffix(javaHome, "Home") {
					addUniqueHome(&homes, seen, javaHome)
				} else {
					// Try Contents/Home subdirectory
					contentsHome := filepath.Join(javaHome, "Contents", "Home")
					if _, err := os.Stat(filepath.Join(contentsHome, "bin", "java")); err == nil {
						addUniqueHome(&homes, seen, contentsHome)
					} else {
						addUniqueHome(&homes, seen, javaHome)
					}
				}
			} else {
				addUniqueHome(&homes, seen, javaHome)
			}
		}
	}
	
	// Method 4: Check common Homebrew installation paths
	homebrewPaths := []string{
		"/opt/homebrew/opt/openjdk",
		"/usr/local/opt/openjdk",
		"/opt/homebrew/Cellar/openjdk",
		"/usr/local/Cellar/openjdk",
	}
	for _, basePath := range homebrewPaths {
		// Check if base path exists and has libexec/openjdk.jdk
		jdkPath := filepath.Join(basePath, "libexec", "openjdk.jdk", "Contents", "Home")
		if _, err := os.Stat(filepath.Join(jdkPath, "bin", "java")); err == nil {
			addUniqueHome(&homes, seen, jdkPath)
		}
		
		// For Cellar paths, enumerate version directories
		if strings.Contains(basePath, "Cellar") {
			entries, err := os.ReadDir(basePath)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					versionPath := filepath.Join(basePath, entry.Name(), "libexec", "openjdk.jdk", "Contents", "Home")
					if _, err := os.Stat(filepath.Join(versionPath, "bin", "java")); err == nil {
						addUniqueHome(&homes, seen, versionPath)
					}
				}
			}
		}
	}
	
	return homes
}

func findJavaHomesLinux(seen map[string]bool) []string {
	var homes []string
	if javaPath, err := exec.LookPath("java"); err == nil {
		if resolved, err := filepath.EvalSymlinks(javaPath); err == nil {
			javaHome := filepath.Dir(filepath.Dir(resolved))
			addUniqueHome(&homes, seen, javaHome)
		}
	}
	return homes
}

func findJavaHomesWindows(seen map[string]bool) []string {
	var homes []string
	if javaPath, err := exec.LookPath("java.exe"); err == nil {
		if resolved, err := filepath.EvalSymlinks(javaPath); err == nil {
			javaHome := filepath.Dir(filepath.Dir(resolved))
			addUniqueHome(&homes, seen, javaHome)
		}
	}

	programFiles := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")}
	for _, base := range programFiles {
		if base == "" {
			continue
		}
		candidateBases := []string{
			filepath.Join(base, "Java"),
			filepath.Join(base, "Eclipse Adoptium"),
		}
		for _, candidateBase := range candidateBases {
			entries, err := os.ReadDir(candidateBase)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				javaHome := filepath.Join(candidateBase, entry.Name())
				javaBin := filepath.Join(javaHome, "bin", "java.exe")
				if _, err := os.Stat(javaBin); err == nil {
					addUniqueHome(&homes, seen, javaHome)
				}
			}
		}
	}

	return homes
}

func addUniqueHome(homes *[]string, seen map[string]bool, home string) bool {
	home = strings.TrimSpace(home)
	if home == "" || seen[home] {
		return false
	}
	seen[home] = true
	*homes = append(*homes, home)
	return true
}

func candidateCacertsPaths(javaHome string) []string {
	return []string{
		filepath.Join(javaHome, "lib", "security", "cacerts"),
		filepath.Join(javaHome, "jre", "lib", "security", "cacerts"),
	}
}

func keytoolBinaryName() string {
	if runtime.GOOS == "windows" {
		return "keytool.exe"
	}
	return "keytool"
}

func ensureKeytoolAvailable(keytoolPath string) error {
	if keytoolPath == "" {
		return errors.New("keytool not found")
	}
	return nil
}

func aliasExists(ctx context.Context, keytoolPath, cacertsPath string) bool {
	cmd := exec.CommandContext(ctx, keytoolPath,
		"-list",
		"-alias", javaCertAlias,
		"-keystore", cacertsPath,
		"-storepass", javaTruststorePassword,
	)
	return cmd.Run() == nil
}

func runKeytool(ctx context.Context, keytoolPath string, args []string) error {
	cmd := exec.CommandContext(ctx, keytoolPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
