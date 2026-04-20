package setup

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/config"
	set_system_proxy "github.com/AikidoSec/safechain-internals/internal/setup/steps/01_set_system_proxy"
	configure_maven "github.com/AikidoSec/safechain-internals/internal/setup/steps/02_configure_maven"
	configure_certificate_trust "github.com/AikidoSec/safechain-internals/internal/setup/steps/03_configure_certificate_trust"
	uninstall_safechain "github.com/AikidoSec/safechain-internals/internal/setup/steps/04_uninstall_safechain"
)

type Runner struct {
	steps     []Step
	uninstall bool
}

func NewRunner(proxyMode string, uninstall bool) *Runner {
	// L4: cert trust + safe-chain cleanup
	// L7: system proxy + maven + cert trust + safe-chain cleanup
	steps := []Step{configure_certificate_trust.New(), uninstall_safechain.New()}
	if proxyMode == config.ProxyModeL7 {
		steps = append([]Step{set_system_proxy.New(), configure_maven.New()}, steps...)
	}
	return &Runner{steps: steps, uninstall: uninstall}
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
	log.Printf("This %s will run %d step(s).\n\n", strings.ToLower(stage), numberOfSteps)

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

	log.Println("================")
	log.Printf("%s complete!\n", stage)

	return nil
}
