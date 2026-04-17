export function formatEventTimeShort(ts: number): string {
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts.toString();
    const diffSec = Math.floor((Date.now() - ts) / 1000);
    if (diffSec >= 0 && diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}min ago`;
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return ts.toString();
  }
}

export function formatEventTime(ts: number): string {
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts.toString();
    const date = d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
    const time = d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    });
    return `${date}, ${time}`;
  } catch {
    return ts.toString();
  }
}

export function isConnectionError(message: string): boolean {
  const s = message.toLowerCase();
  return (
    s.includes("connection refused") ||
    s.includes("fetch failed") ||
    s.includes("network error") ||
    s.includes("net::err_") ||
    s.includes("failed to fetch") ||
    s.includes("dial tcp")
  );
}
