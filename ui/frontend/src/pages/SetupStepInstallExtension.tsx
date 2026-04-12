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
      heading="Network Extension"
      title="Install Network Extension"
      hint="Aikido Endpoint Protection needs to install a network extension to inspect traffic. When prompted, click OK to allow."
      buttonLabel="Install"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
    />
  );
}
