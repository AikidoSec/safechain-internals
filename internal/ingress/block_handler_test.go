package ingress

import "testing"

func TestMapBlockReasonToActivityAction(t *testing.T) {
	tests := []struct {
		reason string
		want   string
		ok     bool
	}{
		{reason: "malware", want: "malware_blocked", ok: true},
		{reason: "rejected", want: "install_blocked", ok: true},
		{reason: "block_all", want: "install_blocked", ok: true},
		{reason: "request_install", want: "install_blocked", ok: true},
		{reason: "new_package", want: "install_blocked", ok: true},
		{reason: "unknown", want: "", ok: false},
	}

	for _, tt := range tests {
		got, ok := mapBlockReasonToActivityAction(tt.reason)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("mapBlockReasonToActivityAction(%q) = (%q, %v), want (%q, %v)", tt.reason, got, ok, tt.want, tt.ok)
		}
	}
}

func TestBuildBlockedActivityEvent(t *testing.T) {
	event := BlockEvent{
		ID:   "evt-1",
		TsMs: 123,
		Artifact: Artifact{
			Product:        "npm",
			PackageName:    "@scope/pkg",
			PackageVersion: "1.2.3",
		},
		BlockReason: "rejected",
	}

	got := buildBlockedActivityEvent(event, "install_blocked")
	if got.Action != "install_blocked" {
		t.Fatalf("expected action install_blocked, got %q", got.Action)
	}
	if len(got.SBOM.Entries) != 1 {
		t.Fatalf("expected 1 ecosystem entry, got %d", len(got.SBOM.Entries))
	}
	entry := got.SBOM.Entries[0]
	if entry.Ecosystem != "npm" {
		t.Fatalf("expected ecosystem npm, got %q", entry.Ecosystem)
	}
	if len(entry.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(entry.Packages))
	}
	pkg := entry.Packages[0]
	if pkg.Id != "@scope/pkg" {
		t.Fatalf("expected package id @scope/pkg, got %q", pkg.Id)
	}
	if pkg.Name != "@scope/pkg" {
		t.Fatalf("expected default package name to fall back to identifier, got %q", pkg.Name)
	}
	if pkg.Version != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %q", pkg.Version)
	}
}

func TestBuildBlockedActivityEventUsesDisplayName(t *testing.T) {
	event := BlockEvent{
		Artifact: Artifact{
			Product:        "chrome",
			PackageName:    "abcdefghijklmnop",
			PackageVersion: "2.0.0",
			DisplayName:    "Readable Extension",
		},
		BlockReason: "malware",
	}

	got := buildBlockedActivityEvent(event, "malware_blocked")
	if got.SBOM.Entries[0].Packages[0].Name != "Readable Extension" {
		t.Fatalf("expected display name to be used, got %q", got.SBOM.Entries[0].Packages[0].Name)
	}
}
