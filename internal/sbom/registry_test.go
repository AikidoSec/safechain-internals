package sbom

import (
	"context"
	"fmt"
	"sort"
	"testing"
)

type mockPackageManager struct {
	name          string
	installations []InstalledVersion
	installErr    error
	packages      map[string][]Package
	sbomErr       error
}

func (m *mockPackageManager) Name() string { return m.name }

func (m *mockPackageManager) Installations(_ context.Context) ([]InstalledVersion, error) {
	return m.installations, m.installErr
}

func (m *mockPackageManager) SBOM(_ context.Context, inst InstalledVersion) ([]Package, error) {
	if m.sbomErr != nil {
		return nil, m.sbomErr
	}
	pkgs, ok := m.packages[inst.Path]
	if !ok {
		return nil, fmt.Errorf("no packages for path %s", inst.Path)
	}
	return pkgs, nil
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("expected non-nil registry")
	}
	if len(r.managers) != 0 {
		t.Fatalf("expected empty managers, got %d", len(r.managers))
	}
}

func TestRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	pm := &mockPackageManager{name: "npm"}

	r.Register(pm)

	got, err := r.Get("npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name() != "npm" {
		t.Fatalf("expected 'npm', got %q", got.Name())
	}
}

func TestGetNotFound(t *testing.T) {
	r := NewRegistry()

	_, err := r.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for missing package manager")
	}
}

func TestRegisterOverwrites(t *testing.T) {
	r := NewRegistry()
	pm1 := &mockPackageManager{name: "npm", installations: []InstalledVersion{{Path: "/first"}}}
	pm2 := &mockPackageManager{name: "npm", installations: []InstalledVersion{{Path: "/second"}}}

	r.Register(pm1)
	r.Register(pm2)

	got, err := r.Get("npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	installs, _ := got.Installations(context.Background())
	if len(installs) != 1 || installs[0].Path != "/second" {
		t.Fatalf("expected overwritten PM with path '/second', got %v", installs)
	}
}

func TestList(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockPackageManager{name: "npm"})
	r.Register(&mockPackageManager{name: "pip"})
	r.Register(&mockPackageManager{name: "vscode"})

	names := r.List()
	sort.Strings(names)

	expected := []string{"npm", "pip", "vscode"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d names, got %d", len(expected), len(names))
	}
	for i, name := range names {
		if name != expected[i] {
			t.Fatalf("expected %q at index %d, got %q", expected[i], i, name)
		}
	}
}

func TestListEmpty(t *testing.T) {
	r := NewRegistry()
	names := r.List()
	if len(names) != 0 {
		t.Fatalf("expected empty list, got %v", names)
	}
}

func TestCollectAllPackages(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockPackageManager{
		name: "npm",
		installations: []InstalledVersion{
			{Version: "18.0.0", Path: "/usr/bin/node", Variant: "node"},
		},
		packages: map[string][]Package{
			"/usr/bin/node": {
				{Name: "express", Version: "4.18.0"},
				{Name: "lodash", Version: "4.17.21"},
			},
		},
	})
	r.Register(&mockPackageManager{
		name: "pip",
		installations: []InstalledVersion{
			{Version: "3.11", Path: "/usr/bin/python3"},
		},
		packages: map[string][]Package{
			"/usr/bin/python3": {
				{Name: "requests", Version: "2.31.0"},
			},
		},
	})

	sbom := r.CollectAllPackages(context.Background())

	if len(sbom.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(sbom.Entries))
	}

	entryByEcosystem := make(map[string]EcosystemEntry)
	for _, e := range sbom.Entries {
		entryByEcosystem[e.Variant] = e
	}

	nodeEntry, ok := entryByEcosystem["node"]
	if !ok {
		t.Fatal("expected 'node' ecosystem entry")
	}
	if nodeEntry.Version != "18.0.0" || len(nodeEntry.Packages) != 2 {
		t.Fatalf("unexpected node entry: %+v", nodeEntry)
	}

	pipEntry, ok := entryByEcosystem["pip"]
	if !ok {
		t.Fatal("expected 'pip' ecosystem entry (fallback from empty Ecosystem)")
	}
	if pipEntry.Version != "3.11" || len(pipEntry.Packages) != 1 {
		t.Fatalf("unexpected pip entry: %+v", pipEntry)
	}
}

func TestCollectAllPackagesEcosystemFallback(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockPackageManager{
		name: "pip",
		installations: []InstalledVersion{
			{Version: "3.11", Path: "/usr/bin/python3"},
		},
		packages: map[string][]Package{
			"/usr/bin/python3": {{Name: "flask", Version: "3.0.0"}},
		},
	})

	sbom := r.CollectAllPackages(context.Background())
	if len(sbom.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(sbom.Entries))
	}
	if sbom.Entries[0].Variant != "pip" {
		t.Fatalf("expected variant fallback to 'pip', got %q", sbom.Entries[0].Variant)
	}
}

func TestCollectAllPackagesInstallationError(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockPackageManager{
		name:       "npm",
		installErr: fmt.Errorf("cannot find npm"),
	})
	r.Register(&mockPackageManager{
		name: "pip",
		installations: []InstalledVersion{
			{Version: "3.11", Path: "/usr/bin/python3"},
		},
		packages: map[string][]Package{
			"/usr/bin/python3": {{Name: "requests", Version: "2.31.0"}},
		},
	})

	sbom := r.CollectAllPackages(context.Background())

	if len(sbom.Entries) != 1 {
		t.Fatalf("expected 1 entry (npm should be skipped), got %d", len(sbom.Entries))
	}
	if sbom.Entries[0].Variant != "pip" {
		t.Fatalf("expected pip entry, got %q", sbom.Entries[0].Variant)
	}
}

func TestCollectAllPackagesSBOMError(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockPackageManager{
		name: "npm",
		installations: []InstalledVersion{
			{Version: "18.0.0", Path: "/usr/bin/node"},
		},
		sbomErr: fmt.Errorf("failed to read packages"),
	})

	sbom := r.CollectAllPackages(context.Background())

	if len(sbom.Entries) != 0 {
		t.Fatalf("expected 0 entries when SBOM fails, got %d", len(sbom.Entries))
	}
}

func TestCollectAllPackagesMultipleInstallations(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockPackageManager{
		name: "pip",
		installations: []InstalledVersion{
			{Version: "3.10", Path: "/usr/bin/python3.10", Variant: "pypi"},
			{Version: "3.11", Path: "/usr/bin/python3.11", Variant: "pypi"},
		},
		packages: map[string][]Package{
			"/usr/bin/python3.10": {{Name: "django", Version: "4.2.0"}},
			"/usr/bin/python3.11": {{Name: "flask", Version: "3.0.0"}},
		},
	})

	sbom := r.CollectAllPackages(context.Background())

	if len(sbom.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(sbom.Entries))
	}

	versions := map[string]bool{}
	for _, e := range sbom.Entries {
		versions[e.Version] = true
		if e.Variant != "pypi" {
			t.Fatalf("expected variant 'pypi', got %q", e.Variant)
		}
	}
	if !versions["3.10"] || !versions["3.11"] {
		t.Fatal("expected both python versions")
	}
}

func TestCollectAllPackagesNoManagers(t *testing.T) {
	r := NewRegistry()
	sbom := r.CollectAllPackages(context.Background())

	if sbom.Entries != nil {
		t.Fatalf("expected nil entries, got %v", sbom.Entries)
	}
}
