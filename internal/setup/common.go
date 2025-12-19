package setup

import (
	"fmt"
	"os"

	"github.com/AikidoSec/safechain-agent/internal/platform"
)

func CreateSetupFinishedMarker() error {
	if err := os.WriteFile(platform.GetProxySetupFinishedMarker(), []byte{}, 0644); err != nil {
		return fmt.Errorf("failed to write setup finished marker: %w", err)
	}
	return nil
}

func RemoveSetupFinishedMarker() error {
	if err := os.Remove(platform.GetProxySetupFinishedMarker()); err != nil {
		return fmt.Errorf("failed to remove setup finished marker: %w", err)
	}
	return nil
}

func CheckSetupFinished() error {
	if _, err := os.Stat(platform.GetProxySetupFinishedMarker()); os.IsNotExist(err) {
		return fmt.Errorf("setup not finished")
	}
	return nil
}
