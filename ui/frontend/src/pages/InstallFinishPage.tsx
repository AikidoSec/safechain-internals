import { useState } from "react";
import { setupRestart } from "../api";
import { getToolIcon } from "../constants";

/** Icon layout: alternating left / right / center column; keys match `constants` TOOL_ICONS. */
const FINISH_ECOSYSTEM_VISUAL: { id: string; align: "left" | "right" | "center" }[] = [
  { id: "pypi", align: "left" },
  { id: "vscode", align: "right" },
  { id: "npm", align: "center" },
  { id: "maven", align: "left" },
  { id: "nuget", align: "right" },
  { id: "chrome", align: "center" },
  { id: "open_vsx", align: "left" },
  { id: "skills_sh", align: "right" },
];

export function InstallFinishPage() {
  const [restarting, setRestarting] = useState(false);
  const [confirming, setConfirming] = useState(false);

  function handleRestartClick() {
    setConfirming(true);
  }

  function handleCancel() {
    setConfirming(false);
  }

  async function handleConfirm() {
    setConfirming(false);
    setRestarting(true);
    try {
      await setupRestart();
    } catch {
      setRestarting(false);
    }
  }

  return (
    <div className="install-page__main">
      {confirming && (
        <div className="install-page__confirm-overlay">
          <div className="install-page__confirm-dialog">
            <p className="install-page__confirm-title">Restart now?</p>
            <p className="install-page__confirm-body">
              Your system will restart immediately. Make sure you&apos;ve saved any open work.
            </p>
            <div className="install-page__confirm-actions">
              <button
                type="button"
                className="button-brand button--tertiary button--normal button--rounded"
                onClick={handleCancel}
              >
                Cancel
              </button>
              <button
                type="button"
                className="button-brand button--normal button--rounded install-page__restart-btn"
                onClick={handleConfirm}
              >
                Restart
              </button>
            </div>
          </div>
        </div>
      )}
      <div className="install-page__finish-grid">
        <div className="install-page__finish-col install-page__finish-col--left">
          <div className="install-page__finish-hero install-page__finish-hero--split">
            <p className="install-page__finish-status">Certificate installed</p>
            <h1 className="install-page__title install-page__title--finish">You&apos;re all set</h1>
            <p className="install-page__lead install-page__followup-lead install-page__lead--finish">
              This device now trusts the Aikido Endpoint certificate. Endpoint Protection can secure traffic from your
              browsers, editors, and package managers while you work.
            </p>
            <div className="install-page__finish-check-wrap">
              <div className="install-page__finish-check" aria-hidden>
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path
                    d="M20 6L9 17l-5-5"
                    stroke="currentColor"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
            </div>
          </div>
          <div className="install-page__restart-card install-page__restart-card--emphasized">
            <p className="install-page__restart-card-title">System restart is highly recommended</p>
            <p className="install-page__restart-card-body">
              A restart ensures all applications pick up the new certificate and network settings. You can restart now or
              do it later from your system menu.
            </p>
            <div className="install-page__restart-card-actions">
              <button
                type="button"
                className="button-brand button--normal button--rounded install-page__restart-btn"
                disabled={restarting}
                onClick={handleRestartClick}
              >
                {restarting ? "Restarting…" : "Restart"}
              </button>
            </div>
          </div>
        </div>

        <section
          className="install-page__ecosystem-section install-page__ecosystem-section--split"
          aria-labelledby="install-finish-ecosystems-heading"
        >
          <h2 id="install-finish-ecosystems-heading" className="install-page__ecosystem-heading">
            Protected ecosystems
          </h2>
          <div className="install-page__ecosystem-timeline">
            <ul className="install-page__ecosystem-rows">
              {FINISH_ECOSYSTEM_VISUAL.map(({ id, align }) => (
                <li key={id} className={`install-page__ecosystem-row install-page__ecosystem-row--${align}`}>
                  <div className="install-page__ecosystem-cell install-page__ecosystem-cell--start">
                    {align === "left" && (
                      <div className="install-page__ecosystem-tile">
                        <img src={getToolIcon(id)} alt="" />
                      </div>
                    )}
                  </div>
                  <div className="install-page__ecosystem-cell install-page__ecosystem-cell--rail">
                    {align === "center" && (
                      <div className="install-page__ecosystem-tile install-page__ecosystem-tile--on-rail">
                        <img src={getToolIcon(id)} alt="" />
                      </div>
                    )}
                  </div>
                  <div className="install-page__ecosystem-cell install-page__ecosystem-cell--end">
                    {align === "right" && (
                      <div className="install-page__ecosystem-tile">
                        <img src={getToolIcon(id)} alt="" />
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>
      </div>
    </div>
  );
}
