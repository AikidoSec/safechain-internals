package setup

import (
	"context"
	"fmt"
	"slices"
)

type Runner struct {
	steps     []Step
	Uninstall bool
	prompter  *Prompter
}

func NewRunner(prompter *Prompter, uninstall bool) *Runner {
	return &Runner{
		steps:     make([]Step, 0),
		prompter:  prompter,
		Uninstall: uninstall,
	}
}

func (r *Runner) AddStep(step Step) {
	r.steps = append(r.steps, step)
}

func (r *Runner) Run(ctx context.Context) error {
	total := len(r.steps)
	if total == 0 {
		r.prompter.Println("No setup steps to run.")
		return nil
	}

	r.prompter.Println("SafeChain Setup")
	r.prompter.Println("================")
	r.prompter.Print("This setup will run %d step(s).\n\n", total)

	if r.Uninstall {
		slices.Reverse(r.steps)
	}

	for i, step := range r.steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		r.prompter.Print("[%d/%d] %s\n", i+1, total, step.Name())
		r.prompter.Print("      %s\n\n", step.Description())

		confirmed, err := r.prompter.Confirm("Proceed with this step?")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if !confirmed {
			r.prompter.Println("Setup cancelled by user.")
			return fmt.Errorf("user declined to proceed with step %q", step.Name())
		}

		if err := step.Run(ctx); err != nil {
			return fmt.Errorf("%q failed: %w", step.Name(), err)
		}

		r.prompter.Println("✓ Step completed successfully")
		r.prompter.Println()
	}

	r.prompter.Println("================")
	r.prompter.Println("Setup complete!")

	if r.Uninstall {
		RemoveSetupFinishedMarker()
	} else {
		if err := CreateSetupFinishedMarker(); err != nil {
			return fmt.Errorf("failed to create setup finished marker: %w", err)
		}
	}
	return nil
}
