import { useEffect, useRef, useState } from "react";
import { startProxy } from "../api";

const RETRY_INTERVAL_MS = 3000;
const TIMEOUT_MS = 2 * 60 * 1000;

interface Props {
  stepNumber: number;
  totalSteps: number;
  onComplete: () => void;
}

export function SetupStepStartProxy({ stepNumber, totalSteps, onComplete }: Props) {
  const [error, setError] = useState("");
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    let cancelled = false;
    const deadline = Date.now() + TIMEOUT_MS;

    async function attempt() {
      while (!cancelled && Date.now() < deadline) {
        try {
          await startProxy();
          if (!cancelled) onComplete();
          return;
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : "Failed to start proxy.";
          if (!cancelled) setError(msg);
          if (Date.now() + RETRY_INTERVAL_MS >= deadline) break;
          await new Promise((r) => setTimeout(r, RETRY_INTERVAL_MS));
        }
      }
    }
    attempt();

    return () => { cancelled = true; };
  }, [onComplete]);

  return (
    <div className="install-page__main" style={{ textAlign: "center", paddingTop: 48 }}>
      <h1 className="install-page__title">Just a few more steps</h1>
      <p className="install-page__lead">
        Step {stepNumber} of {totalSteps}
      </p>
      <div style={{ marginTop: 32 }}>
        <div className="install-page__spinner" />
        <p className="install-page__step-hint" style={{ marginTop: 16 }}>
          Starting proxy…
        </p>
      </div>
    </div>
  );
}
