import { getToolIcon } from "../constants";

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

interface Props {
  stepNumber: number;
  totalSteps: number;
}

export function InstallFinishPage({ stepNumber, totalSteps }: Props) {
  return (
    <div className="install-page__main">
      <div className="install-page__finish-grid">
        <div className="install-page__finish-col install-page__finish-col--left">
          <div className="install-page__finish-hero install-page__finish-hero--split">
            <div className="install-page__finish-step">
              <div className="install-page__step-badge" aria-hidden>
                {stepNumber}
              </div>
              <p className="install-page__finish-status">
                Step {stepNumber} of {totalSteps}
              </p>
            </div>
            <h1 className="install-page__title install-page__title--finish">Restart required</h1>
            <p className="install-page__lead install-page__followup-lead install-page__lead--finish">
              In order for Endpoint Protection to protect your device, you need to restart your computer. Until you do,
              traffic from your browsers, editors, and package managers will not be secured.
            </p>
          </div>
          <div className="install-page__restart-card install-page__restart-card--info">
            <div className="install-page__restart-card-icon">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="10" cy="10" r="10" fill="#6551f3" />
                <text x="10" y="14.5" textAnchor="middle" fill="#fff" fontSize="13" fontWeight="600" fontFamily="system-ui, sans-serif">i</text>
              </svg>
            </div>
            <div className="install-page__restart-card-content">
              <p className="install-page__restart-card-title">Restart to activate protection</p>
              <p className="install-page__restart-card-body">
                A restart is required for all applications to pick up the new certificate and network settings. You can
                restart now or do it later from your system menu.
              </p>
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
