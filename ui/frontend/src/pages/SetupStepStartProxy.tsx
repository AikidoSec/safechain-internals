import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepStartProxy({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      title="Start Proxy"
      hint="Start the Aikido Endpoint proxy so it can begin protecting your traffic."
      buttonLabel="Start"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
    />
  );
}
