import { useEffect, useRef } from "react";
import { startProxy } from "../api";
import { SetupStepLayout } from "./SetupStepLayout";

const RETRY_INTERVAL_MS = 3000;
const TIMEOUT_MS = 2 * 60 * 1000;

interface Props {
  stepNumber: number;
  totalSteps: number;
  onComplete: () => void;
}

export function SetupStepStartProxy({ stepNumber, totalSteps, onComplete }: Props) {
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
        } catch {
          if (Date.now() + RETRY_INTERVAL_MS >= deadline) break;
          await new Promise((r) => setTimeout(r, RETRY_INTERVAL_MS));
        }
      }
    }
    attempt();

    return () => { cancelled = true; };
  }, [onComplete]);

  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="Starting proxy"
      title="Start Proxy"
      hint="Start the Aikido Endpoint proxy so it can begin protecting your traffic."
      buttonLabel="Start"
      workingLabel="Starting..."
      phase="working"
      errorMsg=""
      onAction={() => {}}
    >
      <div className="setup-proxy-loading">
        <div className="setup-proxy-loading__spinner" />
        <p className="setup-proxy-loading__hint">
          This may take a moment. Please wait while the proxy initializes.
        </p>
      </div>
    </SetupStepLayout>
  );
}
