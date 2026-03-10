export type BlockReason = "malware" | "rejected" | "block_all" | "request_install";

export type EventStatus = "" | "blocked" | "request_pending";

export interface BlockedEvent {
  id: string;
  ts: string;
  // The product type (e.g., "npm", "pypi", "vscode", "chrome")
  product: string;
  // The name or identifier of the artifact
  identifier: string;
  // Optional version
  version: string;
  block_reason: BlockReason;
  status?: EventStatus;
 }
