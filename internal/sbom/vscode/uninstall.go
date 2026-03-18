package vscode

import (
	"context"
	"log"
	"slices"

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

	scanner := &VSCodeExtensions{}
	var toUninstall []extensionToUninstall

	// Step 2: Cross-check all installed extensions against the blocklist
	for _, inst := range installations {
		packages, err := scanner.SBOM(ctx, inst)
		if err != nil {
			log.Printf("Failed to collect extensions for %s: %v", inst.Variant, err)
			continue
		}

		var blockList []string

		switch inst.Ecosystem {
		case "vscode":
			blockList = vsCodeBlockList
		case "open_vsx":
			blockList = openVsxBlockList
		}

		for _, pkg := range packages {
			if slices.Contains(blockList, pkg.Id) {
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
