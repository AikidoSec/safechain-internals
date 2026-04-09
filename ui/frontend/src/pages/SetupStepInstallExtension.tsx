import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepInstallExtension({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="Network Extension"
      title="Install Network Extension"
      hint="Aikido Endpoint Protection needs to install a network extension to inspect traffic. When prompted, click OK to allow."
      buttonLabel="Install"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
      aside={
        <aside className="install-page__preview install-page__preview--vpn" aria-hidden>
          <div className="install-page__preview-backdrop install-page__preview-backdrop--vpn">
            <div className="install-page__preview-sheet install-page__preview-sheet--vpn-alert">
              <div className="install-page__preview-vpn-icon-wrap">
                <svg
                  className="install-page__preview-vpn-icon"
                  width="80"
                  height="80"
                  viewBox="0 0 80 80"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                  aria-hidden
                >
                  <path
                    d="M40 10 L14 34 L22 34 L22 62 C22 64.2 23.8 66 26 66 L54 66 C56.2 66 58 64.2 58 62 L58 34 L66 34 Z"
                    fill="#d4d4d8"
                    stroke="#c4c4c8"
                    strokeWidth="1.5"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M40 10 L14 34 L22 34 L58 34 L66 34 Z"
                    fill="#c8c8cc"
                  />
                  <circle cx="40" cy="46" r="12" fill="#6b7280" />
                  <circle cx="40" cy="46" r="5" fill="#d4d4d8" />
                  <circle cx="40" cy="46" r="2.5" fill="#6b7280" />
                </svg>
              </div>

              <p className="install-page__preview-vpn-title">
                &ldquo;Aikido Network Extension&rdquo; would like to use a new network extension
              </p>
              <p className="install-page__preview-vpn-body">
                You can enable this extension in Login Items &amp; Extensions. Network extensions run in the background and can monitor network traffic on your Mac.
              </p>

              <div className="install-page__preview-actions">
                <div className="install-page__preview-mock-btn-spotlight">
                  <button
                    type="button"
                    className="button-brand button--primary button--normal button--rounded install-page__preview-mock-btn install-page__preview-mock-btn--mac-blue"
                    tabIndex={-1}
                  >
                    OK
                  </button>
                </div>
                <button
                  type="button"
                  className="button-brand button--tertiary button--normal button--rounded install-page__preview-mock-btn"
                  tabIndex={-1}
                >
                  Open System Settings
                </button>
              </div>
            </div>
          </div>
        </aside>
      }
    />
  );
}
