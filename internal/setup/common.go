package setup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

func CreateSetupFinishedMarker() error {
	runDir := platform.GetConfig().RunDir
	setupFinishedPath := filepath.Join(runDir, ".setup_finished")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}
	if err := os.WriteFile(setupFinishedPath, []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to write setup finished marker: %w", err)
	}
	return nil
}

func RemoveSetupFinishedMarker() error {
	runDir := platform.GetConfig().RunDir
	setupFinishedPath := filepath.Join(runDir, ".setup_finished")
	if err := os.Remove(setupFinishedPath); err != nil {
		return fmt.Errorf("failed to remove setup finished marker: %w", err)
	}
	return nil
}

func CheckSetupFinished() error {
	runDir := platform.GetConfig().RunDir
	setupFinishedPath := filepath.Join(runDir, ".setup_finished")
	if _, err := os.Stat(setupFinishedPath); os.IsNotExist(err) {
		return fmt.Errorf("setup not finished")
	}
	return nil
}
