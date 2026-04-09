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
      hint="The network extension is installed but needs to be enabled. Click below to open System Settings and approve it."
      buttonLabel="Open Settings"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
    />
  );
}
