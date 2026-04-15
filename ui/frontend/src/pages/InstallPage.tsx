import { useEffect, useState } from "react";
import logoUrl from "../../assets/logo.svg";
import {
  closeInstallWindow,
  getSetupSteps,
  setToken,
  installExtension,
  allowVpn,
  startProxy,
  installProxyCertificate,
  isExtensionInstalled,
  isExtensionActivated,
  isVpnAllowed,
  openExtensionSettings,
  setInstallWindowOnTop,
} from "../api";
import type { Phase } from "./SetupStepLayout";
import { InstallFinishPage } from "./InstallFinishPage";
import { SetupStepToken } from "./SetupStepToken";
import { SetupStepInstallExtension } from "./SetupStepInstallExtension";
import { SetupStepEnableExtension } from "./SetupStepEnableExtension";
import { SetupStepAllowVpn } from "./SetupStepAllowVpn";
import { SetupStepStartProxy } from "./SetupStepStartProxy";
import { SetupStepInstallCa } from "./SetupStepInstallCa";

type StepId = "token" | "install-extension" | "enable-extension" | "allow-vpn" | "start-proxy" | "install-ca";

const VALID_STEPS = new Set<string>(["token", "install-extension", "enable-extension", "allow-vpn", "start-proxy", "install-ca"]);

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollUntil(check: () => Promise<boolean>, intervalMs: number, maxAttempts: number): Promise<boolean> {
  for (let i = 0; i < maxAttempts; i++) {
    await sleep(intervalMs);
    if (await check()) return true;
  }
  return false;
}

const STEP_ACTIONS: Record<StepId, (input?: string) => Promise<void>> = {
  token: (input) => setToken(input ?? ""),
  "install-extension": async () => {
    await installExtension();
    if (await isExtensionInstalled()) return;
    const ok = await pollUntil(isExtensionInstalled, 2000, 15);
    if (!ok) throw new Error("Network extension was not installed. Please retry.");
  },
  "enable-extension": async () => {
    if (await isExtensionActivated()) return;
    await setInstallWindowOnTop(false);
    try {
      await openExtensionSettings();
      const ok = await pollUntil(isExtensionActivated, 2000, 30);
      if (!ok) throw new Error("Network extension was not enabled. Please approve it in System Settings and retry.");
    } finally {
      await setInstallWindowOnTop(true);
    }
  },
  "allow-vpn": async () => {
    await allowVpn();
    if (await isVpnAllowed()) return;
    const ok = await pollUntil(isVpnAllowed, 2000, 15);
    if (!ok) throw new Error("VPN configuration was not allowed. Please approve it and retry.");
  },
  "start-proxy": () => startProxy(),
  "install-ca": () => installProxyCertificate(),
};

export function InstallPage() {
  const [steps, setSteps] = useState<StepId[]>([]);
  const [currentIdx, setCurrentIdx] = useState(0);
  const [phase, setPhase] = useState<Phase>("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const [tokenInput, setTokenInput] = useState("");
  const [showFinish, setShowFinish] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    function poll() {
      getSetupSteps()
        .then((s) => {
          if (cancelled) return;
          const valid = (s ?? []).filter((id): id is StepId => VALID_STEPS.has(id));
          if (valid.length > 0) {
            setSteps(valid);
          } else {
            timer = setTimeout(poll, 500);
          }
        })
        .catch(() => {
          if (!cancelled) timer = setTimeout(poll, 500);
        });
    }
    poll();

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  const currentStep = currentIdx < steps.length ? steps[currentIdx] : null;
  const totalDots = steps.length + 1;

  async function handleAction() {
    if (!currentStep) return;
    if (currentStep === "token" && !tokenInput.trim()) return;

    setPhase("working");
    setErrorMsg("");
    try {
      await STEP_ACTIONS[currentStep](tokenInput.trim());
      if (currentStep === "token") {
        handleNext();
      } else {
        setPhase("done");
      }
    } catch (e: unknown) {
      setPhase("error");
      setErrorMsg(e instanceof Error ? e.message : "Something went wrong. Please try again.");
    }
  }

  function handleNext() {
    setPhase("idle");
    setErrorMsg("");
    setTokenInput("");
    if (currentIdx + 1 >= steps.length) {
      setShowFinish(true);
    } else {
      setCurrentIdx((i) => i + 1);
    }
  }

  async function handleFinish() {
    await closeInstallWindow();
  }

  if (steps.length === 0) {
    return (
      <div className="install-page">
        <header className="install-page__header">
          <img src={logoUrl} alt="Aikido" className="install-page__logo" />
        </header>
        <div className="install-page__scroll">
          <div className="install-page__body install-page__body--followup">
            <div className="install-page__main" style={{ textAlign: "center", paddingTop: 60 }}>
              <p style={{ color: "#6b7280" }}>Loading setup steps…</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const showBottomBar = phase === "done" || showFinish;
  const stepProps = {
    stepNumber: currentIdx + 1,
    totalSteps: steps.length,
    phase,
    errorMsg,
    onAction: handleAction,
  };

  function renderStep() {
    switch (currentStep) {
      case "token":
        return (
          <SetupStepToken
            {...stepProps}
            tokenInput={tokenInput}
            onTokenChange={setTokenInput}
          />
        );
      case "install-extension":
        return <SetupStepInstallExtension {...stepProps} />;
      case "enable-extension":
        return <SetupStepEnableExtension {...stepProps} />;
      case "allow-vpn":
        return <SetupStepAllowVpn {...stepProps} />;
      case "start-proxy":
        return (
          <SetupStepStartProxy
            stepNumber={stepProps.stepNumber}
            totalSteps={stepProps.totalSteps}
            onComplete={handleNext}
          />
        );
      case "install-ca":
        return <SetupStepInstallCa {...stepProps} />;
      default:
        return null;
    }
  }

  return (
    <div className={`install-page${showBottomBar ? " install-page--has-bottom-bar" : ""}`}>
      <header className="install-page__header">
        <img src={logoUrl} alt="Aikido" className="install-page__logo" />
      </header>

      <div className="install-page__dots" role="tablist" aria-label="Setup steps">
        {Array.from({ length: totalDots }, (_, i) => (
          <span
            key={i}
            role="tab"
            aria-selected={showFinish ? i === totalDots - 1 : i === currentIdx}
            className={`install-page__dot${(showFinish ? i === totalDots - 1 : i === currentIdx) ? " install-page__dot--active" : ""}`}
          />
        ))}
      </div>

      <div className="install-page__scroll">
        <div className={`install-page__body${showFinish ? " install-page__body--followup" : ""}`}>
          {showFinish ? <InstallFinishPage /> : renderStep()}
        </div>
      </div>

      {showBottomBar && (
        <div className="install-page__finish-bar">
          <div className="install-page__finish-bar-inner">
            {showFinish ? (
              <button
                type="button"
                className="button-brand button--primary button--normal button--rounded"
                onClick={handleFinish}
              >
                Finish
              </button>
            ) : (
              <button
                type="button"
                className="button-brand button--primary button--normal button--rounded"
                onClick={handleNext}
              >
                Next
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
