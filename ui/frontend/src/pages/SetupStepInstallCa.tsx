import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepInstallCa({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="Just a few more steps"
      title="Install the Aikido Endpoint certificate."
      hint="Aikido Endpoint needs to install a certificate in the system keychain to verify installs secure your device. macOS will ask for your approval."
      buttonLabel="Install"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
    />
  );
}
