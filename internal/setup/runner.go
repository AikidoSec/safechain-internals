package setup

import (
	"context"
	"fmt"
)

type Runner struct {
	steps    []Step
	prompter *Prompter
}

func NewRunner(prompter *Prompter) *Runner {
	return &Runner{
		steps:    make([]Step, 0),
		prompter: prompter,
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
			r.prompter.Println("Skipping step...")
			r.prompter.Println()
			continue
		}

		if err := step.Run(ctx); err != nil {
			return fmt.Errorf("step %q failed: %w", step.Name(), err)
		}

		r.prompter.Println("✓ Step completed successfully")
		r.prompter.Println()
	}

	r.prompter.Println("================")
	r.prompter.Println("Setup complete!")
	return nil
}
