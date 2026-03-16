// Package dockerca installs the Safechain proxy CA certificate into running
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
package dockerca

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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

var debianFamilyIDs = map[string]struct{}{
	"debian":    {},
	"ubuntu":    {},
	"linuxmint": {},
	"pop":       {},
	"kali":      {},
}

var rhelFamilyIDs = map[string]struct{}{
	"rhel":      {},
	"centos":    {},
	"fedora":    {},
	"amzn":      {},
	"rocky":     {},
	"almalinux": {},
	"ol":        {},
}

func InstallCAOnRunningContainers(ctx context.Context) error {
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

	cmd, err := platform.CommandAsCurrentUserWithPathEnv(ctx, dockerBinary,
		"events",
		"--filter", "type=container",
		"--filter", "event=start",
		"--format", "{{.Actor.ID}}",
	)
	if err != nil {
		return fmt.Errorf("build docker events watcher: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("docker events stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("docker events stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start docker events watcher: %w", err)
	}

	log.Println("Docker CA: watching container start events")

	stderrDone := make(chan string, 1)
	go func() {
		// Cap stderr capture to 4 KiB — enough for any error message from
		// docker events, prevents unbounded memory growth on long-running watchers.
		b, err := io.ReadAll(io.LimitReader(stderr, 4096))
		if err != nil {
			log.Printf("Docker CA: error reading docker events stderr: %v", err)
		}
		stderrDone <- strings.TrimSpace(string(b))
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		containerID := strings.TrimSpace(scanner.Text())
		if containerID == "" {
			continue
		}

		log.Printf("Docker CA: container start event received: %s", containerID)
		if err := installCAInContainer(ctx, dockerBinary, containerID); err != nil {
			log.Printf("Docker CA: failed to update started container %s: %v", containerID, err)
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("read docker events: %w", err)
	}

	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		errOutput := <-stderrDone
		if errOutput != "" {
			return fmt.Errorf("docker events watcher failed: %w: %s", err, errOutput)
		}
		return fmt.Errorf("docker events watcher failed: %w", err)
	}

	return nil
}

func installCAInContainer(ctx context.Context, dockerBinary, containerID string) error {
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
			"apk add --no-cache ca-certificates",
			"mkdir -p /usr/local/share/ca-certificates",
			"cp /tmp/" + certName + " /usr/local/share/ca-certificates/" + certName,
			"update-ca-certificates",
		}, " && ")
	case installMethodDebian:
		// Three-step fallback to avoid slow apt-get update when not needed:
		// 1. update-ca-certificates directly (works if ca-certificates is already installed)
		// 2. apt-get install without update (works if the image has a fresh package index from its own build)
		// 3. full apt-get update + install (slow fallback for truly bare images like debian:latest)
		return "mkdir -p /usr/local/share/ca-certificates" +
			" && cp /tmp/" + certName + " /usr/local/share/ca-certificates/" + certName +
			" && (update-ca-certificates 2>/dev/null" +
			" || (DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates 2>/dev/null && update-ca-certificates)" +
			" || (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates && update-ca-certificates))"
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

func isAlpine(id string) bool {
	return id == "alpine"
}

func isDebianFamily(id, idLike string) bool {
	if _, ok := debianFamilyIDs[id]; ok {
		return true
	}
	return strings.Contains(idLike, "debian") || strings.Contains(idLike, "ubuntu")
}

func isRHELFamily(id, idLike string) bool {
	if _, ok := rhelFamilyIDs[id]; ok {
		return true
	}
	return strings.Contains(idLike, "rhel") || strings.Contains(idLike, "fedora") || strings.Contains(idLike, "centos")
}

func parseOSRelease(contents string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		values[key] = strings.Trim(value, `"`)
	}
	return values
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
