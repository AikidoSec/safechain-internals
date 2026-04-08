import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
  tokenInput: string;
  onTokenChange: (value: string) => void;
}

export function SetupStepToken({ stepNumber, totalSteps, phase, errorMsg, onAction, tokenInput, onTokenChange }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      title="Enter your Aikido token"
      hint="Paste your Aikido agent token to connect this device to your organization."
      buttonLabel="Set Token"
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
