import * as DaemonService from "../bindings/endpoint-protection-ui/daemonservice.js";
import type { BlockEvent } from "./types";

export async function listEvents(limit: number): Promise<BlockEvent[]> {
  return (await DaemonService.ListEvents(limit)) as BlockEvent[];
}

export async function getEvent(eventId: string): Promise<BlockEvent> {
  return (await DaemonService.GetEvent(eventId)) as BlockEvent;
}

export async function requestAccess(
  eventId: string
): Promise<BlockEvent> {
  return (await DaemonService.RequestAccess(eventId)) as BlockEvent;
}
