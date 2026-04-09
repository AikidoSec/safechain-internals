import type { ReactNode } from "react";

export type Phase = "idle" | "working" | "done" | "error";

export interface SetupStepLayoutProps {
  stepNumber: number;
  totalSteps: number;
  title: string;
  hint: string;
  buttonLabel: string;
  workingLabel?: string;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
  disabled?: boolean;
  children?: ReactNode;
  aside?: ReactNode;
}

export function SetupStepLayout({
  stepNumber,
  totalSteps,
  title,
  hint,
  buttonLabel,
  phase,
  errorMsg,
  onAction,
  workingLabel = "Working…",
  disabled,
  children,
  aside,
}: SetupStepLayoutProps) {
  return (
    <>
      <div className="install-page__main">
        <h1 className="install-page__title">Just a few more steps</h1>
        <p className="install-page__lead">
          Step {stepNumber} of {totalSteps}
        </p>
        <ol className="install-page__steps">
          <li className={`install-page__step${phase === "done" ? " install-page__step--done" : ""}`}>
            <div className="install-page__step-badge" aria-hidden>
              {stepNumber}
            </div>
            <div className="install-page__step-body">
              <div className="install-page__step-row">
                <div>
                  <p className="install-page__step-title">{title}</p>
                  <p className="install-page__step-hint">{hint}</p>
                  {children}
                </div>
                <button
                  type="button"
                  className="button-brand button--primary button--normal button--rounded install-page__action-btn"
                  onClick={onAction}
                  disabled={phase === "working" || phase === "done" || disabled}
                >
                  {phase === "working"
                    ? workingLabel
                    : phase === "done"
                      ? "Done ✓"
                      : buttonLabel}
                </button>
              </div>
            </div>
          </li>

          {phase === "error" && (
            <li className="install-page__step install-page__step--result install-page__step--failure">
              <div className="install-page__step-badge install-page__step-badge--muted" aria-hidden>
                !
              </div>
              <div className="install-page__step-body">
                <p className="install-page__step-title install-page__step-title--result">Step failed</p>
                <p className="install-page__step-error install-page__step-error--block">{errorMsg}</p>
                <div className="install-page__retry-row">
                  <button
                    type="button"
                    className="button-brand button--primary button--normal button--rounded install-page__action-btn"
                    onClick={onAction}
                  >
                    Retry
                  </button>
                </div>
              </div>
            </li>
          )}

          {phase === "done" && (
            <li className="install-page__step install-page__step--result install-page__step--success">
              <div className="install-page__step-badge install-page__step-badge--muted" aria-hidden>
                ✓
              </div>
              <div className="install-page__step-body">
                <p className="install-page__step-title install-page__step-title--result">Step completed</p>
                <p className="install-page__next-hint">
                  Select <strong>Next</strong> to continue.
                </p>
              </div>
            </li>
          )}
        </ol>
      </div>
      {aside}
    </>
  );
}
