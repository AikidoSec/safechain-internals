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
