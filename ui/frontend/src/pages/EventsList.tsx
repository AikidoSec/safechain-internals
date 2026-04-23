import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import type { BlockEvent } from "../types";
import { Events } from "@wailsio/runtime";
import { listEvents } from "../api";
import { BLOCK_REASON_LABEL, getToolIcon } from "../constants";
import { formatEventTimeShort, isConnectionError } from "../utils";
import { useDashboardContext } from "../App";

function updateEventInList(events: BlockEvent[], updated: BlockEvent): BlockEvent[] {
  return events.map((event) => (event.id === updated.id ? updated : event));
}

export function EventsList() {
  const navigate = useNavigate();
  const { setupRequired, onStartSetup } = useDashboardContext();
  const [events, setEvents] = useState<BlockEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listEvents(50);
      setEvents(list ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const unsub = Events.On("permissions_updated", (ev: unknown) => {
      // refresh the events list
      load();
    });
    return () => { unsub(); };
  }, [load]);

  useEffect(() => {
    const unsub = Events.On("blocked", (ev: unknown) => {
      const payload = (ev as { data?: BlockEvent }).data;
      if (payload) setEvents((prev) => [payload, ...prev]);
    });
    return () => {
      unsub();
    };
  }, []);

  useEffect(() => {
    const unsub = Events.On("blocked_updated", (ev: unknown) => {
      const payload = (ev as { data?: BlockEvent }).data;
      if (payload) {
        setEvents((prev) => updateEventInList(prev, payload));
      }
    });
    return () => {
      unsub();
    };
  }, []);


  const connectionFailed = error !== null && isConnectionError(error);

  return (
    <div className="events-list">
      <h1>Events</h1>
      {setupRequired && (
        <div className="events-list-setup-required" role="alert">
          <p className="events-list-setup-required__text">
            Initial setup is incomplete. Aikido Endpoint Protection is not protecting this device yet —{" "}
            <button
              type="button"
              className="events-list-setup-required__link"
              onClick={onStartSetup}
            >
              click “System Setup Required…”
            </button>{" "}
            to finish configuration.
          </p>
        </div>
      )}
      {loading && <p className="events-list-loading">Loading…</p>}
      {error && !connectionFailed && (
        <div className="events-list-error-inline">
          <p className="error">{error}</p>
        </div>
      )}
      {error && connectionFailed && (
        <div className="events-list-connection-message">
          <h2>Can't connect to Aikido Endpoint Protection daemon</h2>
          <p className="events-list-connection-message-subtitle">
            The app couldn't reach the Aikido Endpoint Protection daemon. Make sure it's running, then try again.
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
                <th>Package</th>
                <th>Time</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr
                  key={ev.id}
                  onClick={() => navigate(`/events/${ev.id}`)}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") navigate(`/events/${ev.id}`); }}
                  tabIndex={0}
                  role="button"
                  className="row-clickable"
                >
                  <td className="event-identifier">
                    <span className="event-identifier-content">
                      <img
                        src={getToolIcon(ev.artifact.product)}
                        alt={ev.artifact.product}
                        className="event-product-icon"
                      />
                      <span className="event-identifier-text">
                        {ev.artifact.display_name ?? ev.artifact.identifier}
                      </span>
                      {ev.count !== undefined && ev.count > 1 && (
                        <span className="event-count-badge" aria-label={`${ev.count} blocked events`}>
                          x{ev.count}
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="event-time">{formatEventTimeShort(ev.ts_ms)}</td>
                  <td>
                    {ev.status === "request_approved" ? (
                      <span className="status status-approved">approved</span>
                    ) : ev.status === "request_pending" ? (
                      <span className="status status-pending">requested</span>
                    ) : ev.status === "request_rejected" ? (
                      <span className="status status-rejected">rejected</span>
                    ) : (
                      <span className={`reason-badge reason-badge--${ev.block_reason}`}>
                        {BLOCK_REASON_LABEL[ev.block_reason] ?? ev.block_reason}
                      </span>
                    )}
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
            When Aikido Endpoint Protection blocks an installation or extension, it will appear here. You can then open it to request access.
          </p>
        </div>
      )}
    </div>
  );
}
