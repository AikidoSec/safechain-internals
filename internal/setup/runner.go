package setup

import (
	"context"
	"fmt"
	"log"
	"slices"

	install_proxy_ca "github.com/AikidoSec/safechain-agent/internal/setup/steps/01_install_proxy_ca"
	set_system_proxy "github.com/AikidoSec/safechain-agent/internal/setup/steps/02_set_system_proxy"
)

type Runner struct {
	steps     []Step
	uninstall bool
}

func NewRunner(uninstall bool) *Runner {
	return &Runner{
		steps: []Step{
			install_proxy_ca.New(),
			set_system_proxy.New(),
		},
		uninstall: uninstall,
	}
}

func (r *Runner) Run(ctx context.Context) error {
	total := len(r.steps)
	if total == 0 {
		log.Println("No setup steps to run.")
		return nil
	}

	log.Println("SafeChain Setup")
	log.Println("================")
	log.Printf("This setup will run %d step(s).\n\n", total)

	if r.uninstall {
		slices.Reverse(r.steps)
	}

	for i, step := range r.steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		name := step.InstallName()
		description := step.InstallDescription()
		if r.uninstall {
			name = step.UninstallName()
			description = step.UninstallDescription()
		}

		log.Printf("[%d/%d] %s\n", i+1, total, name)
		log.Printf("      %s\n\n", description)

		functionToRun := step.Install
		if r.uninstall {
			functionToRun = step.Uninstall
		}

		if err := functionToRun(ctx); err != nil {
			return fmt.Errorf("%q failed: %w", name, err)
		}

		log.Println("Step completed successfully")
		log.Println()
	}

	if r.uninstall {
		RemoveSetupFinishedMarker()
	} else {
		if err := CreateSetupFinishedMarker(); err != nil {
			return fmt.Errorf("failed to create setup finished marker: %w", err)
		}
	}

	log.Println("================")
	log.Println("Setup complete!")

	return nil
}
