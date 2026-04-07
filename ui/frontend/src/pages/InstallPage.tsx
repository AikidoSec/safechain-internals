import { useState } from "react";
import logoUrl from "../../assets/logo.svg";
import { closeInstallWindow, installProxyCertificate } from "../api";
import { InstallFinishPage } from "./InstallFinishPage";

type Phase = "idle" | "working" | "done";

export function InstallPage() {
  const [wizardStep, setWizardStep] = useState(0);
  const [phase, setPhase] = useState<Phase>("idle");
  const [success, setSuccess] = useState<boolean | null>(null);

  async function handleInstall() {
    setPhase("working");
    try {
      await installProxyCertificate();
      setSuccess(true);
      setPhase("done");
    } catch {
      setSuccess(false);
      setPhase("done");
    }
  }

  async function handleFinish() {
    await closeInstallWindow();
  }

  const done = phase === "done";
  const step1ButtonDisabled = phase === "working" || success === true;
  const step1ButtonLabel = phase === "working" ? "Installing…" : success === true ? "Installed" : "Install";

  const showBottomBar = (wizardStep === 0 && success === true) || wizardStep === 1;

  return (
    <div className={`install-page${showBottomBar ? " install-page--has-bottom-bar" : ""}`}>
      <header className="install-page__header">
        <img src={logoUrl} alt="Aikido" className="install-page__logo" />
      </header>

      <div className="install-page__dots" role="tablist" aria-label="Setup steps">
        <span
          role="tab"
          aria-selected={wizardStep === 0}
          className={`install-page__dot${wizardStep === 0 ? " install-page__dot--active" : ""}`}
        />
        <span
          role="tab"
          aria-selected={wizardStep === 1}
          className={`install-page__dot${wizardStep === 1 ? " install-page__dot--active" : ""}`}
        />
      </div>

      <div className="install-page__scroll">
        <div className={`install-page__body${wizardStep === 1 ? " install-page__body--followup" : ""}`}>
          {wizardStep === 1 ? (
            <InstallFinishPage />
          ) : (
            <>
              <div className="install-page__main">
                <h1 className="install-page__title">Just a few more steps</h1>
                <ol className="install-page__steps">
                  <li className={`install-page__step${success === true ? " install-page__step--done" : ""}`}>
                    <div className="install-page__step-badge" aria-hidden>
                      1
                    </div>
                    <div className="install-page__step-body">
                      <div className="install-page__step-row">
                        <div>
                          <p className="install-page__step-title">Install the Aikido Endpoint certificate.</p>
                          <p className="install-page__step-hint">
                            Aikido Endpoint needs to install a certificate in the system keychain to verify installs secure your device. macOS will ask for your approval.
                          </p>
                        </div>
                        <button
                          type="button"
                          className="button-brand button--primary button--normal button--rounded install-page__action-btn"
                          onClick={handleInstall}
                          disabled={step1ButtonDisabled}
                        >
                          {step1ButtonLabel}
                        </button>
                      </div>
                    </div>
                  </li>

                  {done && (
                    <li
                      className={`install-page__step install-page__step--result${
                        success ? " install-page__step--success" : " install-page__step--failure"
                      }`}
                    >
                      <div className="install-page__step-badge install-page__step-badge--muted" aria-hidden>
                        2
                      </div>
                      <div className="install-page__step-body">
                        {success ? (
                          <>
                            <p className="install-page__step-title install-page__step-title--result">Installation complete</p>
                            <div className="install-page__result-success">
                              <p>Aikido Endpoint Protection has been installed successfully.</p>
                            </div>
                            <p className="install-page__next-hint">Select <strong>Next</strong> to continue.</p>
                          </>
                        ) : (
                          <>
                            <p className="install-page__step-title install-page__step-title--result">Installation failed</p>
                            <p className="install-page__step-error install-page__step-error--block">
                              The certificate could not be installed. Please try again.
                            </p>
                            <div className="install-page__retry-row">
                              <button
                                type="button"
                                className="button-brand button--primary button--normal button--rounded install-page__action-btn"
                                onClick={handleInstall}
                              >
                                Retry
                              </button>
                            </div>
                          </>
                        )}
                      </div>
                    </li>
                  )}
                </ol>
              </div>

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
            </>
          )}
        </div>
      </div>

      {showBottomBar && (
        <div className="install-page__finish-bar">
          <div className="install-page__finish-bar-inner">
            {wizardStep === 0 ? (
              <button
                type="button"
                className="button-brand button--primary button--normal button--rounded"
                onClick={() => setWizardStep(1)}
              >
                Next
              </button>
            ) : (
              <button
                type="button"
                className="button-brand button--primary button--normal button--rounded"
                onClick={handleFinish}
              >
                Finish
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
