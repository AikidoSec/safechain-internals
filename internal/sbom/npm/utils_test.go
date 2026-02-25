package npm

import (
	"sort"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

func TestCollectDependenciesEmpty(t *testing.T) {
	packages := collectDependencies(nil, make(map[string]bool))
	if len(packages) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(packages))
	}
}

func TestCollectDependenciesFlat(t *testing.T) {
	deps := map[string]npmDependency{
		"express": {Version: "4.18.0"},
		"lodash":  {Version: "4.17.21"},
	}

	packages := collectDependencies(deps, make(map[string]bool))
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}

	byName := packagesByName(packages)
	assertPackage(t, byName, "express", "4.18.0")
	assertPackage(t, byName, "lodash", "4.17.21")
}

func TestCollectDependenciesNested(t *testing.T) {
	deps := map[string]npmDependency{
		"nodemon": {
			Version: "3.1.11",
			Dependencies: map[string]npmDependency{
				"chokidar": {
					Version: "3.6.0",
					Dependencies: map[string]npmDependency{
						"anymatch": {Version: "3.1.3"},
						"braces":   {Version: "3.0.3"},
					},
				},
				"debug": {
					Version: "4.4.3",
					Dependencies: map[string]npmDependency{
						"ms": {Version: "2.1.3"},
					},
				},
			},
		},
	}

	packages := collectDependencies(deps, make(map[string]bool))
	if len(packages) != 6 {
		t.Fatalf("expected 6 packages, got %d", len(packages))
	}

	byName := packagesByName(packages)
	assertPackage(t, byName, "nodemon", "3.1.11")
	assertPackage(t, byName, "chokidar", "3.6.0")
	assertPackage(t, byName, "anymatch", "3.1.3")
	assertPackage(t, byName, "braces", "3.0.3")
	assertPackage(t, byName, "debug", "4.4.3")
	assertPackage(t, byName, "ms", "2.1.3")
}

func TestCollectDependenciesSkipsEmptyVersion(t *testing.T) {
	deps := map[string]npmDependency{
		"express":  {Version: "4.18.0"},
		"fsevents": {Version: ""},
		"phantom":  {},
	}

	packages := collectDependencies(deps, make(map[string]bool))
	if len(packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(packages))
	}
	assertPackage(t, packagesByName(packages), "express", "4.18.0")
}

func TestCollectDependenciesDeduplicates(t *testing.T) {
	deps := map[string]npmDependency{
		"a": {
			Version: "1.0.0",
			Dependencies: map[string]npmDependency{
				"shared": {Version: "2.0.0"},
			},
		},
		"b": {
			Version: "1.0.0",
			Dependencies: map[string]npmDependency{
				"shared": {Version: "2.0.0"},
			},
		},
	}

	packages := collectDependencies(deps, make(map[string]bool))

	count := 0
	for _, p := range packages {
		if p.Name == "shared" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 'shared' to appear once, got %d", count)
	}
	if len(packages) != 3 {
		t.Fatalf("expected 3 packages (a, b, shared), got %d", len(packages))
	}
}

func TestCollectDependenciesDifferentVersionsNotDeduplicated(t *testing.T) {
	deps := map[string]npmDependency{
		"a": {
			Version: "1.0.0",
			Dependencies: map[string]npmDependency{
				"shared": {Version: "2.0.0"},
			},
		},
		"b": {
			Version: "1.0.0",
			Dependencies: map[string]npmDependency{
				"shared": {Version: "3.0.0"},
			},
		},
	}

	packages := collectDependencies(deps, make(map[string]bool))

	versions := []string{}
	for _, p := range packages {
		if p.Name == "shared" {
			versions = append(versions, p.Version)
		}
	}
	sort.Strings(versions)
	if len(versions) != 2 || versions[0] != "2.0.0" || versions[1] != "3.0.0" {
		t.Fatalf("expected shared@2.0.0 and shared@3.0.0, got %v", versions)
	}
}

func TestCollectDependenciesDeeplyNested(t *testing.T) {
	deps := map[string]npmDependency{
		"a": {
			Version: "1.0.0",
			Dependencies: map[string]npmDependency{
				"b": {
					Version: "2.0.0",
					Dependencies: map[string]npmDependency{
						"c": {
							Version: "3.0.0",
							Dependencies: map[string]npmDependency{
								"d": {Version: "4.0.0"},
							},
						},
					},
				},
			},
		},
	}

	packages := collectDependencies(deps, make(map[string]bool))
	if len(packages) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(packages))
	}

	byName := packagesByName(packages)
	assertPackage(t, byName, "a", "1.0.0")
	assertPackage(t, byName, "b", "2.0.0")
	assertPackage(t, byName, "c", "3.0.0")
	assertPackage(t, byName, "d", "4.0.0")
}

func packagesByName(packages []sbom.Package) map[string]sbom.Package {
	m := make(map[string]sbom.Package)
	for _, p := range packages {
		m[p.Name] = p
	}
	return m
}

func assertPackage(t *testing.T, byName map[string]sbom.Package, name, version string) {
	t.Helper()
	p, ok := byName[name]
	if !ok {
		t.Fatalf("expected package %q not found", name)
	}
	if p.Version != version {
		t.Fatalf("expected %s@%s, got %s@%s", name, version, p.Name, p.Version)
	}
}
