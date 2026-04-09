import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepInstallCa({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="Just a few more steps"
      title="Install the Aikido Endpoint certificate."
      hint="Aikido Endpoint needs to install a certificate in the system keychain to verify installs secure your device. macOS will ask for your approval."
      buttonLabel="Install"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
      aside={
        <aside className="install-page__preview" aria-hidden>
          <div className="install-page__preview-backdrop">
            <div className="install-page__preview-sheet">
              <div className="install-page__preview-icon-wrap">
                <svg
                  className="install-page__preview-lock"
                  width="72"
                  height="72"
                  viewBox="0 0 72 72"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <defs>
                    <linearGradient id="installLockGold" x1="20" y1="36" x2="52" y2="64" gradientUnits="userSpaceOnUse">
                      <stop stopColor="#FDE68A" />
                      <stop offset="0.35" stopColor="#EAB308" />
                      <stop offset="1" stopColor="#B45309" />
                    </linearGradient>
                  </defs>
                  <path
                    d="M23 36V27a13 13 0 0126 0v9"
                    stroke="#B8B8BE"
                    strokeWidth="5.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <rect x="17" y="34" width="38" height="30" rx="7" fill="url(#installLockGold)" />
                </svg>
                <span className="install-page__preview-exec-badge">
                  <span className="install-page__preview-exec-text">exec</span>
                </span>
              </div>

              <h2 className="install-page__preview-heading">security</h2>

              <p className="install-page__preview-blurb">
                You are making changes to the System Certificate Trust Settings. Enter your password to allow this.
              </p>

              <div className="install-page__preview-fields install-page__preview-fields--sheet">
                <div className="install-page__preview-field">Current User</div>
                <div className="install-page__preview-field install-page__preview-field--password install-page__preview-field--focused">
                  ••••••••
                </div>
              </div>

              <div className="install-page__preview-actions">
                <button
                  type="button"
                  className="button-brand button--primary button--normal button--rounded install-page__preview-mock-btn install-page__preview-mock-btn--mac-blue"
                  tabIndex={-1}
                >
                  Update Settings
                </button>
                <button
                  type="button"
                  className="button-brand button--tertiary button--normal button--rounded install-page__preview-mock-btn"
                  tabIndex={-1}
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </aside>
      }
    />
  );
}
