import * as DaemonService from "../bindings/endpoint-protection-ui/daemonservice.js";
import type { BlockEvent, TlsTerminationFailedEvent } from "./types";

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

export async function getVersion(): Promise<string> {
  return DaemonService.GetVersion();
}
