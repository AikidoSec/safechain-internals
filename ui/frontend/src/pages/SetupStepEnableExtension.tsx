import { SetupStepLayout, type Phase } from "./SetupStepLayout";
import appIconUrl from "../../assets/icon_1024x1024.png";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepEnableExtension({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="Network Extension"
      title="Enable Network Extension"
      hint="System Settings will open to the Network Extensions page. Enable the toggle next to Aikido Network Extension."
      buttonLabel="Open Settings"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
      aside={
        <aside className="install-page__preview install-page__preview--vpn" aria-hidden>
          <div className="install-page__preview-backdrop install-page__preview-backdrop--vpn">
            <div className="sysext-settings-preview">
              <div className="sysext-settings-preview__header">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden>
                  <path
                    d="M10 2 L3 8.5 L5 8.5 L5 16 C5 16.6 5.4 17 6 17 L14 17 C14.6 17 15 16.6 15 16 L15 8.5 L17 8.5 Z"
                    fill="#9ca3af"
                  />
                  <circle cx="10" cy="11.5" r="3" fill="#6b7280" />
                  <circle cx="10" cy="11.5" r="1.2" fill="#9ca3af" />
                </svg>
                <div>
                  <p className="sysext-settings-preview__title">Network Extensions</p>
                </div>
              </div>

              <div className="sysext-settings-preview__row">
                <div className="sysext-settings-preview__app-icon">
                  <img src={appIconUrl} alt="" width="28" height="28" style={{ borderRadius: 6 }} />
                </div>
                <div className="sysext-settings-preview__app-info">
                  <p className="sysext-settings-preview__app-name">Aikido Network Extension</p>
                  <p className="sysext-settings-preview__app-desc">Aikido Network Extension Sysext</p>
                </div>
                <div className="install-page__preview-mock-btn-spotlight">
                  <div className="sysext-settings-preview__toggle">
                    <div className="sysext-settings-preview__toggle-track">
                      <div className="sysext-settings-preview__toggle-thumb" />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </aside>
      }
    />
  );
}
