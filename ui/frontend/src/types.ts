export type BlockReason = "malware" | "rejected" | "block_all" | "request_install";

export type EventStatus = "" | "blocked" | "request_pending";

export interface Artifact {
  product: string;
  identifier: string;
  version?: string;
}

export interface BlockEvent {
  id: string;
  ts_ms: number;
  // The product type (e.g., "npm", "pypi", "vscode", "chrome")
  artifact: Artifact;
  block_reason: BlockReason;
  status?: EventStatus;
 }
