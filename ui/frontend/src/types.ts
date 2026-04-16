export type BlockReason = "malware" | "rejected" | "block_all" | "request_install" | "new_package";

export type EventStatus = "" | "blocked" | "request_pending" | "request_approved" | "request_rejected";

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
  count?: number;
}

export interface TlsTerminationFailedEvent {
  id?: string;
  ts_ms: number;
  sni: string;
  app?: string;
  app_path?: string;
  error: string;
}
