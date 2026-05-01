import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
  tokenInput: string;
  onTokenChange: (value: string) => void;
  invalidToken?: boolean;
}

export function SetupStepToken({ stepNumber, totalSteps, phase, errorMsg, onAction, tokenInput, onTokenChange, invalidToken = false }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="Connect your device"
      title={invalidToken ? "Replace your Aikido token" : "Enter your Aikido token"}
      hint={
        invalidToken
          ? "The configured token was rejected by Aikido. Paste a valid Endpoint Protection token to reconnect this device."
          : "Paste your Aikido Endpoint Protection token to connect this device to your organization."
      }
      buttonLabel={invalidToken ? "Replace Token" : "Set Token"}
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
      disabled={!tokenInput.trim()}
    >
      <input
        type="text"
        className="install-page__token-input"
        placeholder="Paste token here…"
        value={tokenInput}
        onChange={(e) => onTokenChange(e.target.value)}
        disabled={phase === "working" || phase === "done"}
        onKeyDown={(e) => {
          if (e.key === "Enter" && tokenInput.trim()) onAction();
        }}
      />
    </SetupStepLayout>
  );
}
