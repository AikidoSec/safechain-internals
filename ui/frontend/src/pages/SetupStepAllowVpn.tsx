import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepAllowVpn({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      title="Allow VPN Configuration"
      hint="Aikido needs to create a local VPN configuration to route traffic through the proxy. macOS will ask for your approval."
      buttonLabel="Allow"
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
                  <defs>
                    <radialGradient id="vpnIconGlow" cx="50%" cy="45%" r="65%">
                      <stop offset="0%" stopColor="#c4b5fd" />
                      <stop offset="45%" stopColor="#7c3aed" />
                      <stop offset="100%" stopColor="#4c1d95" />
                    </radialGradient>
                    <linearGradient id="vpnPortMetal" x1="28" y1="34" x2="52" y2="52" gradientUnits="userSpaceOnUse">
                      <stop stopColor="#e8e8ec" />
                      <stop offset="1" stopColor="#9ca3af" />
                    </linearGradient>
                  </defs>
                  <circle cx="40" cy="40" r="36" fill="url(#vpnIconGlow)" />
                  <ellipse
                    cx="40"
                    cy="40"
                    rx="28"
                    ry="10"
                    stroke="rgba(255,255,255,0.35)"
                    strokeWidth="1.25"
                    fill="none"
                    transform="rotate(-18 40 40)"
                  />
                  <ellipse
                    cx="40"
                    cy="40"
                    rx="22"
                    ry="26"
                    stroke="rgba(255,255,255,0.22)"
                    strokeWidth="1"
                    fill="none"
                    transform="rotate(52 40 40)"
                  />
                  <ellipse
                    cx="40"
                    cy="40"
                    rx="30"
                    ry="14"
                    stroke="rgba(255,255,255,0.18)"
                    strokeWidth="1"
                    fill="none"
                    transform="rotate(78 40 40)"
                  />
                  <rect x="30" y="34" width="20" height="18" rx="3" fill="url(#vpnPortMetal)" />
                  <rect x="33" y="38" width="14" height="7" rx="1" fill="#374151" />
                  <rect x="34.2" y="40" width="2" height="3" rx="0.4" fill="#fbbf24" />
                  <rect x="37.5" y="40" width="2" height="3" rx="0.4" fill="#fbbf24" />
                  <rect x="40.8" y="40" width="2" height="3" rx="0.4" fill="#fbbf24" />
                </svg>
              </div>

              <p className="install-page__preview-vpn-title">
                &ldquo;Aikido Network Extension&rdquo; Would Like to Add Proxy Configurations
              </p>
              <p className="install-page__preview-vpn-body">
                All network activity on this Mac may be filtered or monitored.
              </p>

              <div className="install-page__preview-actions install-page__preview-actions--vpn-row">
                <div className="install-page__preview-mock-btn-spotlight">
                  <button
                    type="button"
                    className="button-brand button--tertiary button--normal button--rounded install-page__preview-mock-btn install-page__preview-mock-btn--vpn-secondary"
                    tabIndex={-1}
                  >
                    Allow
                  </button>
                </div>
                <button
                  type="button"
                  className="button-brand button--primary button--normal button--rounded install-page__preview-mock-btn install-page__preview-mock-btn--vpn-primary"
                  tabIndex={-1}
                >
                  Don&apos;t Allow
                </button>
              </div>
            </div>
          </div>
        </aside>
      }
    />
  );
}
