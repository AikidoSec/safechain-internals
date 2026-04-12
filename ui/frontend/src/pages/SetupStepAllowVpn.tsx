import { SetupStepLayout, type Phase } from "./SetupStepLayout";

interface Props {
  stepNumber: number;
  totalSteps: number;
  phase: Phase;
  errorMsg: string;
  onAction: () => void;
}

export function SetupStepAllowVpn({ stepNumber, totalSteps, phase, errorMsg, onAction }: Props) {
  return (
    <SetupStepLayout
      stepNumber={stepNumber}
      totalSteps={totalSteps}
      heading="VPN Configuration"
      title="Allow VPN Configuration"
      hint="Aikido needs to create a local VPN configuration to route traffic through the proxy. macOS will ask for your approval."
      buttonLabel="Allow"
      phase={phase}
      errorMsg={errorMsg}
      onAction={onAction}
    />
  );
}
