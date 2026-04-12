import { SetupStepLayout, type Phase } from "./SetupStepLayout";

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
    />
  );
}
