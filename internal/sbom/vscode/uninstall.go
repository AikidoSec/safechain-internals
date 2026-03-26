package vscode

import (
	"context"
	"log"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type extensionToUninstall struct {
	binaryPath  string
	extensionId string
}

func UninstallBlockedExtensions(ctx context.Context, vsCodeBlockList []string, openVsxBlockList []string) {
	// Step 1: Collect SBOM - discover all editor installations and their extensions
	installations, err := findInstallations(ctx)
	if err != nil {
		log.Printf("Failed to find VSCode installations for extension uninstall check: %v", err)
		return
	}

	if len(installations) == 0 {
		return
	}

	vsCodeBlockSet := make(map[string]struct{}, len(vsCodeBlockList))
	for _, id := range vsCodeBlockList {
		vsCodeBlockSet[id] = struct{}{}
	}
	openVsxBlockSet := make(map[string]struct{}, len(openVsxBlockList))
	for _, id := range openVsxBlockList {
		openVsxBlockSet[id] = struct{}{}
	}

	scanner := &VSCodeExtensions{}
	var toUninstall []extensionToUninstall

	// Step 2: Cross-check all installed extensions against the blocklist
	for _, inst := range installations {
		packages, err := scanner.SBOM(ctx, inst)
		if err != nil {
			log.Printf("Failed to collect extensions for %s: %v", inst.Variant, err)
			continue
		}

		var blockSet map[string]struct{}

		switch inst.Ecosystem {
		case "vscode":
			blockSet = vsCodeBlockSet
		case "open_vsx":
			blockSet = openVsxBlockSet
		}

		for _, pkg := range packages {
			if _, blocked := blockSet[pkg.Id]; blocked {
				toUninstall = append(toUninstall, extensionToUninstall{
					binaryPath:  inst.Path,
					extensionId: pkg.Id,
				})
			}
		}
	}

	// Step 3: Uninstall blocked extensions one by one
	for _, ext := range toUninstall {
		log.Printf("Uninstalling blocked extension %s using %s", ext.extensionId, ext.binaryPath)
		if err := uninstallExtension(ctx, ext.binaryPath, ext.extensionId); err != nil {
			log.Printf("Failed to uninstall extension %s: %v", ext.extensionId, err)
			continue
		}
		log.Printf("Successfully uninstalled extension %s", ext.extensionId)
	}
}

func uninstallExtension(ctx context.Context, binaryPath string, extensionId string) error {
	_, err := platform.RunAsCurrentUserWithPathEnv(ctx, binaryPath, "--uninstall-extension", extensionId)
	return err
}
