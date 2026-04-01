export type BlockReason = "malware" | "rejected" | "block_all" | "request_install";

export type EventStatus = "" | "blocked" | "request_pending" | "request_approved";

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

export interface EcosystemExceptions {
  allowed_packages: string[];
  rejected_packages: string[];
}

export interface EcosystemPermissions {
  block_all_installs: boolean;
  request_installs: boolean;
  minimum_allowed_age_timestamp: number;
  exceptions: EcosystemExceptions;
}

export interface PermissionsResponse {
  permission_group: { id: number; name: string };
  ecosystems: Record<string, EcosystemPermissions>;
}

export interface TlsTerminationFailedEvent {
  id?: string;
  ts_ms: number;
  sni: string;
  app?: string;
  error: string;
}
