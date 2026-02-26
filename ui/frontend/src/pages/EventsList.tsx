import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { BlockedEvent } from "../types";
import { Events } from "@wailsio/runtime";
import { listEvents } from "../api";
import npmIcon from "../../assets/npm.svg";
import pypiIcon from "../../assets/pypi.svg";
import vscodeIcon from "../../assets/vscode.svg";

const TOOL_ICONS: Record<string, string> = {
  npm: npmIcon,
  pip: pypiIcon,
  pypi: pypiIcon,
  vscode: vscodeIcon,
};

function formatEventTime(ts: string): string {
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
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
    return ts;
  }
}

function isConnectionError(message: string): boolean {
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

export function EventsList() {
  const navigate = useNavigate();
  const [events, setEvents] = useState<BlockedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listEvents(50);
      // sort by ts descending
      list.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
      setEvents(list ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    const unsub = Events.On("blocked", (ev: { data?: BlockedEvent }) => {
      const payload = ev.data;
      if (payload) setEvents((prev) => [payload, ...prev]);
    });
    return () => {
      unsub();
    };
  }, []);


  const connectionFailed = error !== null && isConnectionError(error);

  return (
    <div className="events-list">
      <h1>Recent blocked events</h1>
      {loading && <p className="events-list-loading">Loading…</p>}
      {error && !connectionFailed && (
        <div className="events-list-error-inline">
          <p className="error">{error}</p>
        </div>
      )}
      {error && connectionFailed && (
        <div className="events-list-connection-message">
          <h2>Can't connect to SafeChain daemon</h2>
          <p className="events-list-connection-message-subtitle">
            The app couldn't reach the SafeChain daemon. Make sure it's running, then try again.
          </p>
          <button
            type="button"
            className="button-brand button--primary button--normal button--rounded"
            onClick={load}
            disabled={loading}
          >
            Try again
          </button>
        </div>
      )}
      {!connectionFailed && events.length > 0 && (
        <div className="events-list-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Tool</th>
                <th>Time</th>
                <th>Identifier</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr
                  key={ev.id}
                  onClick={() => navigate(`/events/${ev.id}`)}
                  className="row-clickable"
                >
                  <td className="event-product">
                    {TOOL_ICONS[ev.product?.toLowerCase()] ? (
                      <img
                        src={TOOL_ICONS[ev.product.toLowerCase()]}
                        alt={ev.product}
                        className="event-product-icon"
                      />
                    ) : (
                      ev.product
                    )}
                  </td>
                  <td className="event-time">{formatEventTime(ev.ts)}</td>
                  <td className="event-identifier" title={ev.identifier}>
                    {ev.identifier}
                  </td>
                  <td>
                    <span className={`status status-blocked`}>blocked</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {!loading && !error && events.length === 0 && (
        <div className="events-list-empty-state">
          <div className="events-list-empty-state-icon" aria-hidden>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M9 22V12h6v10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h2 className="events-list-empty-state-title">No blocked events</h2>
          <p className="events-list-empty-state-subtitle">
            When SafeChain blocks an installation or extension, it will appear here. You can then open it to request access.
          </p>
        </div>
      )}
    </div>
  );
}
