import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepInstallExtension({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      title="Install Network Extension"
      hint="Aikido Endpoint Protection requires a network extension to inspect traffic. macOS will ask for your approval."
      buttonLabel="Install"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
    />
  );
}
