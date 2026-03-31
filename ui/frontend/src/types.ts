export type BlockReason = "malware" | "rejected" | "block_all" | "request_install";

export type EventStatus = "" | "blocked" | "request_pending";

export interface Artifact {
  product: string;
  identifier: string;
  version?: string;
  display_name?: string;
}

export interface BlockEvent {
  id: string;
  ts_ms: number;
  artifact: Artifact;
  block_reason: BlockReason;
  status?: EventStatus;
}

export interface TlsTerminationFailedEvent {
  id?: string;
  ts_ms: number;
  sni: string;
  app?: string;
  error: string;
}
