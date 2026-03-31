// Package docker installs the Safechain proxy CA certificate into running
// Docker containers. The following Linux distributions are supported:
//
//   - Debian family (Debian, Ubuntu, Linux Mint, Pop!_OS, Kali): via
//     update-ca-certificates in /usr/local/share/ca-certificates/
//   - Alpine: via apk add ca-certificates then update-ca-certificates;
//     the ca-certificates package is installed automatically if absent
//   - RHEL family (RHEL, CentOS, Fedora, Amazon Linux, Rocky, AlmaLinux, Oracle Linux):
//     via update-ca-trust in /etc/pki/ca-trust/source/anchors/
//
// Unsupported distributions (e.g. Arch, openSUSE, distroless/scratch images)
// are detected and skipped with a warning log.
package docker

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

const installedCertName = "aikido-safechain-proxy-ca.crt"

type installMethod string

const (
	installMethodUnknown installMethod = ""
	installMethodDebian  installMethod = "debian"
	installMethodAlpine  installMethod = "alpine"
	installMethodRHEL    installMethod = "rhel"
)

// Configurator implements the certconfig Configurator interface for Docker containers.
type Configurator struct{}

func New() *Configurator {
	return &Configurator{}
}

func (c *Configurator) Name() string {
	return "docker"
}

func (c *Configurator) Install(ctx context.Context) error {
	return InstallDockerCA(ctx)
}

// Uninstall is a no-op: containers are ephemeral, and removing CAs from
// running containers at teardown would be fragile and of little value.
func (c *Configurator) Uninstall(_ context.Context) error {
	log.Println("Docker CA: skipping uninstall (containers are ephemeral)")
	return nil
}

func InstallDockerCA(ctx context.Context) error {
	dockerBinary, err := findDockerBinary()
	if err != nil {
		log.Println("Docker CA: docker binary not found, skipping reconcile")
		return nil
	}

	containerIDsOutput, err := platform.RunAsCurrentUserWithPathEnv(ctx, dockerBinary, "ps", "-q")
	if err != nil {
		return fmt.Errorf("list running containers: %w", err)
	}

	containerIDs := splitNonEmptyLines(containerIDsOutput)
	if len(containerIDs) == 0 {
		log.Println("Docker CA: no running containers detected")
		return nil
	}

	log.Printf("Docker CA: reconciling %d running container(s)", len(containerIDs))
	for _, containerID := range containerIDs {
		if err := installCAInContainer(ctx, dockerBinary, containerID); err != nil {
			log.Printf("Docker CA: failed to update container %s: %v", containerID, err)
		}
	}

	return nil
}

func WatchContainerStarts(ctx context.Context) error {
	dockerBinary, err := findDockerBinary()
	if err != nil {
		log.Println("Docker CA: docker binary not found, skipping event watcher")
		return nil
	}

	return watchContainerStarts(ctx, dockerBinary)
}

func ProbeDockerDaemon(ctx context.Context) error {
	dockerBinary, err := findDockerBinary()
	if err != nil {
		log.Println("Docker CA: docker binary not found, skipping daemon probe")
		return nil
	}

	if _, err := platform.RunAsCurrentUserWithPathEnv(ctx, dockerBinary, "info", "--format", "{{.ServerVersion}}"); err != nil {
		return fmt.Errorf("probe docker daemon: %w", err)
	}

	return nil
}

// containerIDRe matches a valid Docker container ID: 12 (short) or 64 (full)
// lowercase hex characters, as returned by `docker ps -q` and `docker events`.
var containerIDRe = regexp.MustCompile(`^[0-9a-f]{12}$|^[0-9a-f]{64}$`)

// isValidContainerID reports whether id is a valid Docker container ID.
func isValidContainerID(id string) bool {
	return containerIDRe.MatchString(id)
}

func installCAInContainer(ctx context.Context, dockerBinary, containerID string) error {
	if !isValidContainerID(containerID) {
		return fmt.Errorf("skipping container: invalid ID %q (expected 12 or 64 hex chars)", containerID)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	method, prettyName, err := detectInstallMethod(ctx, dockerBinary, containerID)
	if err != nil {
		return err
	}
	if method == installMethodUnknown {
		log.Printf("Docker CA: skipping container %s (%s): OS not supported (supported: Debian family, Alpine, RHEL family)", containerID, prettyName)
		return nil
	}

	certPath := proxy.GetCaCertPath()
	if certPath == "" {
		return fmt.Errorf("proxy CA cert path is empty")
	}

	log.Printf("Docker CA: installing CA into container %s (%s)", containerID, prettyName)

	if _, err := platform.RunAsCurrentUserWithPathEnv(ctx, dockerBinary, "cp", certPath, containerID+":/tmp/"+installedCertName); err != nil {
		return fmt.Errorf("copy CA into container: %w", err)
	}

	script := buildInstallScript(method, installedCertName)
	log.Printf("Docker CA: waiting for %s to finish (may take a few minutes if package lists need fetching)", containerID)
	if _, err := platform.RunAsCurrentUserWithPathEnv(ctx, dockerBinary, "exec", containerID, "sh", "-c", script); err != nil {
		return fmt.Errorf("refresh trust store: %w", err)
	}
	log.Printf("Docker CA: trust store updated successfully in %s", containerID)

	return nil
}

// buildInstallScript returns the shell command to install certName (already
// present at /tmp/<certName>) into the system trust store for the given distro
// family. The returned script is safe to pass directly to `sh -c`.
func buildInstallScript(method installMethod, certName string) string {
	switch method {
	case installMethodAlpine:
		return strings.Join([]string{
			// Skip the network install if the package is already present.
			"apk info -e ca-certificates || apk add --no-cache ca-certificates",
			"mkdir -p /usr/local/share/ca-certificates",
			"cp /tmp/" + certName + " /usr/local/share/ca-certificates/" + certName,
			"update-ca-certificates",
		}, " && ")
	case installMethodDebian:
		// Three-step fallback to avoid slow apt-get update when not needed:
		// 1. update-ca-certificates directly (works if ca-certificates is already installed)
		// 2. apt-get install without update (works if the image has a fresh package index from its own build)
		// 3. full apt-get update + install (slow fallback for truly bare images like debian:latest)
		refreshTrust := "(update-ca-certificates 2>/dev/null" +
			" || (DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates 2>/dev/null && update-ca-certificates)" +
			" || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates && update-ca-certificates))"
		return strings.Join([]string{
			"mkdir -p /usr/local/share/ca-certificates",
			"cp /tmp/" + certName + " /usr/local/share/ca-certificates/" + certName,
			refreshTrust,
		}, " && ")
	case installMethodRHEL:
		return strings.Join([]string{
			"mkdir -p /etc/pki/ca-trust/source/anchors",
			"cp /tmp/" + certName + " /etc/pki/ca-trust/source/anchors/" + certName,
			"update-ca-trust",
		}, " && ")
	default:
		return ""
	}
}

func detectInstallMethod(ctx context.Context, dockerBinary, containerID string) (installMethod, string, error) {
	// The `sh -c ...` command runs inside the target container via `docker exec`,
	// not on the host. We use it to read the Linux container's /etc/os-release.
	output, err := platform.RunAsCurrentUserWithPathEnv(ctx, dockerBinary, "exec", containerID, "sh", "-c", "cat /etc/os-release 2>/dev/null || true")
	if err != nil {
		return installMethodUnknown, "", fmt.Errorf("read os-release: %w", err)
	}

	method, prettyName := detectMethodFromOSRelease(output)
	log.Printf("Docker CA: container %s detected as %q (method=%s)", containerID, prettyName, method)
	return method, prettyName, nil
}

// detectMethodFromOSRelease determines the install method and pretty name from
// the raw contents of /etc/os-release.
func detectMethodFromOSRelease(contents string) (installMethod, string) {
	osRelease := parseOSRelease(contents)
	prettyName := osRelease["PRETTY_NAME"]
	if prettyName == "" {
		prettyName = "unknown"
	}

	id := strings.ToLower(osRelease["ID"])
	idLike := strings.ToLower(osRelease["ID_LIKE"])

	switch {
	case isAlpine(id):
		return installMethodAlpine, prettyName
	case isDebianFamily(id, idLike):
		return installMethodDebian, prettyName
	case isRHELFamily(id, idLike):
		return installMethodRHEL, prettyName
	default:
		return installMethodUnknown, prettyName
	}
}

// splitNonEmptyLines normalizes Docker CLI output that is expected to be a
// simple newline-delimited list (for example `docker ps -q`, which returns
// values like "abc123\ndef456\n"). We trim each line and drop blanks so
// trailing newlines do not produce empty entries.
func splitNonEmptyLines(output string) []string {
	scanner := bufio.NewScanner(strings.NewReader(output))
	var result []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
