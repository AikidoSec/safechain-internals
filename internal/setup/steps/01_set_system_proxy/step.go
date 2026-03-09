package set_system_proxy

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type Step struct {
}

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Set System PAC"
}

func (s *Step) InstallDescription() string {
	return "Configures the system-level PAC to route traffic through SafeChain Proxy"
}

func (s *Step) UninstallName() string {
	return "Remove System PAC"
}

func (s *Step) UninstallDescription() string {
	return "Removes the system-level PAC configuration that routes traffic through SafeChain Proxy"
}

func (s *Step) Install(ctx context.Context) error {
	err := proxy.LoadProxyConfig()
	if err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}
	proxySet, err := platform.IsAnySystemProxySet(ctx)
	if err != nil {
		return fmt.Errorf("failed to check system proxy/PAC: %v", err)
	}
	if proxySet {
		msg := "system proxy or PAC is already set; installation cannot continue to avoid proxy conflicts"
		details, detailErr := platform.GetSystemProxyConflictDetails(ctx)
		if len(details) > 0 {
			msg = fmt.Sprintf(
				"%s. Where it is set:\n%s\nTo install SafeChain, disable or remove the proxy/PAC on these entries first, then restart the SafeChain service.",
				msg,
				strings.Join(details, "\n"),
			)
		} else {
			msg = msg + " To install SafeChain, disable any system proxy or PAC (e.g. in system network settings), then restart the SafeChain service."
			if detailErr != nil {
				msg = msg + " (Details could not be retrieved: " + detailErr.Error() + ")"
			}
		}
		return fmt.Errorf("%s", msg)
	}
	if err := platform.SetSystemPAC(ctx, proxy.MetaPacURL); err != nil {
		return fmt.Errorf("failed to set system PAC: %v", err)
	}
	if err := platform.IsSystemPACSet(ctx, proxy.MetaPacURL); err != nil {
		return fmt.Errorf("could not verify if system PAC is set: %v", err)
	}
	log.Println("System PAC set successfully")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	if err := platform.IsSystemPACSet(ctx, proxy.MetaPacURL); err != nil {
		return fmt.Errorf("system PAC is not set: %v! Failing uninstallation to avoid proxy conflicts!", err)
	}
	return platform.UnsetSystemPAC(ctx, proxy.MetaPacURL)
}
