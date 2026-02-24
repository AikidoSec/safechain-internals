import * as DaemonService from "../bindings/changeme/daemonservice.js";
import type { BlockedEvent } from "./types";

export async function listEvents(limit: number): Promise<BlockedEvent[]> {
  return DaemonService.ListEvents(limit);
}

export async function getEvent(eventId: string): Promise<BlockedEvent> {
  return DaemonService.GetEvent(eventId);
}

export async function requestAccess(
  eventId: string,
  message: string
): Promise<void> {
  return DaemonService.RequestAccess(eventId, message);
}
