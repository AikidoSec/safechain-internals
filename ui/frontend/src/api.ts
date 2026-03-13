import * as DaemonService from "../bindings/endpoint-protection-ui/daemonservice.js";
import type { BlockEvent } from "./types";

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
