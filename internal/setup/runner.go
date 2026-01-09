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
	stage := "Setup"
	if r.uninstall {
		stage = "Teardown"
		slices.Reverse(r.steps)
	}

	numberOfSteps := len(r.steps)
	if numberOfSteps == 0 {
		log.Println("No steps to run.")
		return nil
	}

	log.Println("SafeChain", stage)
	log.Println("================")
	log.Printf("%s will run %d step(s).\n\n", stage, numberOfSteps)

	for i, step := range r.steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		name := step.InstallName()
		description := step.InstallDescription()
		functionToRun := step.Install
		if r.uninstall {
			name = step.UninstallName()
			description = step.UninstallDescription()
			functionToRun = step.Uninstall
		}

		log.Printf("[%d/%d] %s\n", i+1, numberOfSteps, name)
		log.Printf("      %s\n\n", description)

		if err := functionToRun(ctx); err != nil {
			return fmt.Errorf("%q failed: %w", name, err)
		}

		log.Printf("%s step completed successfully\n\n", stage)
	}

	if r.uninstall {
		RemoveSetupFinishedMarker()
	} else {
		if err := CreateSetupFinishedMarker(); err != nil {
			return fmt.Errorf("failed to create setup finished marker: %w", err)
		}
	}

	log.Println("================")
	log.Printf("%s complete!\n", stage)

	return nil
}
