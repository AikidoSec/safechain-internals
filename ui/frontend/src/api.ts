import * as DaemonService from "../bindings/endpoint-protection-ui/daemonservice.js";
import type { BlockEvent, MinPackageAgeEvent, TlsTerminationFailedEvent } from "./types";

export async function listEvents(limit: number): Promise<BlockEvent[]> {
  return DaemonService.ListEvents(limit);
}

export async function getEvent(eventId: string): Promise<BlockEvent> {
  return DaemonService.GetEvent(eventId);
}

export async function requestAccess(
  eventId: string
): Promise<void> {
  return DaemonService.RequestAccess(eventId);
}

export async function listTlsEvents(limit: number): Promise<TlsTerminationFailedEvent[]> {
  return DaemonService.ListTlsEvents(limit);
}

export async function getTlsEvent(eventId: string): Promise<TlsTerminationFailedEvent> {
  return DaemonService.GetTlsEvent(eventId);
}

export async function listMinPackageAgeEvents(limit: number): Promise<MinPackageAgeEvent[]> {
  return DaemonService.ListMinPackageAgeEvents(limit);
}

export async function getMinPackageAgeEvent(eventId: string): Promise<MinPackageAgeEvent> {
  return DaemonService.GetMinPackageAgeEvent(eventId);
}

export async function getVersion(): Promise<string> {
  return DaemonService.GetVersion();
}

export async function installProxyCertificate(): Promise<void> {
  return DaemonService.InstallProxyCertificate();
}

export async function setToken(token: string): Promise<void> {
  return DaemonService.SetToken(token);
}

export async function installExtension(): Promise<void> {
  return DaemonService.InstallExtension();
}

export async function allowVpn(): Promise<void> {
  return DaemonService.AllowVpn();
}

export async function startProxy(): Promise<void> {
  return DaemonService.StartProxy();
}

export async function isExtensionInstalled(): Promise<boolean> {
  return DaemonService.IsExtensionInstalled();
}

export async function isExtensionActivated(): Promise<boolean> {
  return DaemonService.IsExtensionActivated();
}

export async function isVpnAllowed(): Promise<boolean> {
  return DaemonService.IsVpnAllowed();
}

export async function openExtensionSettings(): Promise<void> {
  return DaemonService.OpenExtensionSettings();
}

export async function setInstallWindowOnTop(onTop: boolean): Promise<void> {
  return DaemonService.SetInstallWindowOnTop(onTop);
}

export async function getSetupSteps(): Promise<string[]> {
  return DaemonService.GetSetupSteps();
}

export async function setupRestart(): Promise<void> {
  return DaemonService.SetupRestart();
}

export async function setupCheck(): Promise<boolean> {
  return DaemonService.SetupCheck();
}

export async function setupStart(): Promise<void> {
  return DaemonService.SetupStart();
}

export async function closeInstallWindow(): Promise<void> {
  return DaemonService.CloseInstallWindow();
}

export async function collectLogs(): Promise<void> {
  return DaemonService.CollectLogs();
}

export async function openDashboardToEvent(eventId: string, eventType: string): Promise<void> {
  return DaemonService.OpenDashboardToEvent(eventId, eventType);
}

export async function closeTrayNotification(): Promise<void> {
  return DaemonService.CloseTrayNotification();
}
