package docker

import (
	"strings"
	"testing"
)

// assertEqual fails the test immediately when got != want, printing both values.
func assertEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseOSRelease(t *testing.T) {
	values := parseOSRelease(`
# Comment line should be ignored
NAME="Debian GNU/Linux"
ID=debian
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID_LIKE=debian
MALFORMED_LINE
`)

	assertEqual(t, values["ID"], "debian")
	assertEqual(t, values["PRETTY_NAME"], "Debian GNU/Linux 12 (bookworm)")
	assertEqual(t, values["ID_LIKE"], "debian")
	if _, exists := values["MALFORMED_LINE"]; exists {
		t.Fatal("expected malformed line to be ignored")
	}
}

func TestDetectDebianFamily(t *testing.T) {
	testCases := []struct {
		name   string
		id     string
		idLike string
		want   bool
	}{
		{name: "debian", id: "debian", want: true},
		{name: "ubuntu", id: "ubuntu", want: true},
		{name: "kali", id: "kali", want: true},
		{name: "debian-like", id: "custom", idLike: "something debian", want: true},
		{name: "alpine", id: "alpine", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqual(t, isDebianFamily(tc.id, tc.idLike), tc.want)
		})
	}
}

func TestIsAlpine(t *testing.T) {
	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "matches alpine", id: "alpine", want: true},
		{name: "debian not matched", id: "debian", want: false},
		// isAlpine receives a pre-lowercased string from detectMethodFromOSRelease;
		// uppercase should never match.
		{name: "case sensitive", id: "ALPINE", want: false},
		{name: "empty", id: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqual(t, isAlpine(tc.id), tc.want)
		})
	}
}

func TestDetectMethodFromOSRelease(t *testing.T) {
	testCases := []struct {
		name       string
		osRelease  string
		wantMethod installMethod
		wantPretty string
	}{
		{
			name: "alpine",
			osRelease: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.18.0
PRETTY_NAME="Alpine Linux v3.18"`,
			wantMethod: installMethodAlpine,
			wantPretty: "Alpine Linux v3.18",
		},
		{
			name: "debian",
			osRelease: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
ID=debian
ID_LIKE=debian`,
			wantMethod: installMethodDebian,
			wantPretty: "Debian GNU/Linux 12 (bookworm)",
		},
		{
			name: "ubuntu",
			osRelease: `NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"`,
			wantMethod: installMethodDebian,
			wantPretty: "Ubuntu 22.04.3 LTS",
		},
		{
			name: "rhel",
			osRelease: `NAME="Red Hat Enterprise Linux"
VERSION="9.3 (Plow)"
ID="rhel"
ID_LIKE="fedora"
PRETTY_NAME="Red Hat Enterprise Linux 9.3 (Plow)"`,
			wantMethod: installMethodRHEL,
			wantPretty: "Red Hat Enterprise Linux 9.3 (Plow)",
		},
		{
			name: "fedora",
			osRelease: `NAME="Fedora Linux"
ID=fedora
PRETTY_NAME="Fedora Linux 43 (Container Image)"`,
			wantMethod: installMethodRHEL,
			wantPretty: "Fedora Linux 43 (Container Image)",
		},
		{
			name: "amazon linux",
			osRelease: `NAME="Amazon Linux"
ID="amzn"
ID_LIKE="fedora"
PRETTY_NAME="Amazon Linux 2023"`,
			wantMethod: installMethodRHEL,
			wantPretty: "Amazon Linux 2023",
		},
		{
			name:       "scratch/distroless (no os-release)",
			osRelease:  "",
			wantMethod: installMethodUnknown,
			wantPretty: "unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			method, prettyName := detectMethodFromOSRelease(tc.osRelease)
			assertEqual(t, method, tc.wantMethod)
			assertEqual(t, prettyName, tc.wantPretty)
		})
	}
}

func TestBuildInstallScript(t *testing.T) {
	testCases := []struct {
		name     string
		method   installMethod
		certName string
		contains []string
	}{
		{
			name:     "debian",
			method:   installMethodDebian,
			certName: "my-ca.crt",
			contains: []string{
				"mkdir -p /usr/local/share/ca-certificates",
				"my-ca.crt",
				"update-ca-certificates",
				"apt-get install",
				"ca-certificates",
			},
		},
		{
			name:     "alpine includes apk add before update-ca-certificates",
			method:   installMethodAlpine,
			certName: "my-ca.crt",
			contains: []string{
				"apk info -e ca-certificates",
				"apk add --no-cache ca-certificates",
				"mkdir -p /usr/local/share/ca-certificates",
				"my-ca.crt",
				"update-ca-certificates",
			},
		},
		{
			name:     "rhel",
			method:   installMethodRHEL,
			certName: "my-ca.crt",
			contains: []string{
				"/etc/pki/ca-trust/source/anchors",
				"my-ca.crt",
				"update-ca-trust",
			},
		},
		{
			name:     "debian does not invoke apk",
			method:   installMethodDebian,
			certName: "my-ca.crt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			script := buildInstallScript(tc.method, tc.certName)
			for _, want := range tc.contains {
				if !strings.Contains(script, want) {
					t.Fatalf("script missing %q\ngot: %s", want, script)
				}
			}
		})
	}

	// Debian must not include the Alpine package manager.
	if strings.Contains(buildInstallScript(installMethodDebian, "ca.crt"), "apk") {
		t.Fatal("debian script must not invoke apk")
	}

	// RHEL must use its own trust store, not the Debian one.
	rhelScript := buildInstallScript(installMethodRHEL, "ca.crt")
	if strings.Contains(rhelScript, "update-ca-certificates") {
		t.Fatal("rhel script must not invoke update-ca-certificates")
	}
	if strings.Contains(rhelScript, "/usr/local/share/ca-certificates") {
		t.Fatal("rhel script must not use debian cert path")
	}

	// Alpine must install the ca-certificates package before updating the trust store.
	alpineScript := buildInstallScript(installMethodAlpine, "ca.crt")
	if strings.Index(alpineScript, "apk add") > strings.Index(alpineScript, "update-ca-certificates") {
		t.Fatalf("apk add must precede update-ca-certificates in alpine script\ngot: %s", alpineScript)
	}
}

func TestIsValidContainerID(t *testing.T) {
	testCases := []struct {
		id   string
		want bool
	}{
		// valid short ID (12 hex chars)
		{id: "abc123def456", want: true},
		// valid full ID (64 hex chars)
		{id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", want: true},
		// uppercase hex rejected
		{id: "ABC123DEF456", want: false},
		// wrong length (11 chars)
		{id: "abc123def45", want: false},
		// wrong length (13 chars)
		{id: "abc123def4567", want: false},
		// non-hex characters
		{id: "abc123defxyz", want: false},
		// path traversal attempt
		{id: "../../../etc/passwd:", want: false},
		// empty
		{id: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			assertEqual(t, isValidContainerID(tc.id), tc.want)
		})
	}
}

func TestSplitNonEmptyLines(t *testing.T) {
	got := splitNonEmptyLines("abc123\n\ndef456\n")

	assertEqual(t, len(got), 2)
	assertEqual(t, got[0], "abc123")
	assertEqual(t, got[1], "def456")
}
