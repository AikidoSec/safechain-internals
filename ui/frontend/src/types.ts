export interface BlockedEvent {
  id: string;
  ts: string;
  // The product type (e.g., "npm", "pypi", "vscode", "chrome")
  product: string;
  // The name or identifier of the artifact
  identifier: string;
  // Optional version
  version: string;
  bypass_enabled: boolean;
 }
