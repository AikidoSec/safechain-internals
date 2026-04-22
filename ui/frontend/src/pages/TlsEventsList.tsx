import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import type { TlsTerminationFailedEvent } from "../types";
import { Events } from "@wailsio/runtime";
import { collectLogs, listTlsEvents } from "../api";
import { formatEventTime, isConnectionError } from "../utils";

export function TlsEventsList() {
  const navigate = useNavigate();
  const [events, setEvents] = useState<TlsTerminationFailedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [collecting, setCollecting] = useState(false);
  const [collectMessage, setCollectMessage] = useState<string | null>(null);
  const [confirmingCollect, setConfirmingCollect] = useState(false);

  const handleCollectLogsClick = useCallback(() => {
    setCollectMessage(null);
    setConfirmingCollect(true);
  }, []);

  const handleCollectCancel = useCallback(() => {
    setConfirmingCollect(false);
  }, []);

  const handleCollectConfirm = useCallback(async () => {
    setConfirmingCollect(false);
    setCollecting(true);
    setCollectMessage(null);
    try {
      await collectLogs();
      setCollectMessage("Logs uploaded successfully.");
    } catch (e) {
      setCollectMessage(
        `Failed to upload logs: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setCollecting(false);
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listTlsEvents(50);
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
    const unsub = Events.On("tls_termination_failed", (ev: unknown) => {
      const payload = (ev as { data?: TlsTerminationFailedEvent }).data;
      if (payload) setEvents((prev) => [payload, ...prev]);
    });
    return () => {
      unsub();
    };
  }, []);

  const connectionFailed = error !== null && isConnectionError(error);

  return (
    <div className="events-list">
      <div className="events-list-header">
        <h1>Logs</h1>
        <button
          type="button"
          className="button-brand button--primary button--normal button--rounded"
          onClick={handleCollectLogsClick}
          disabled={collecting}
        >
          {collecting ? "Uploading…" : "Upload Logs"}
        </button>
      </div>
      {collectMessage && (
        <p className="events-list-collect-message">{collectMessage}</p>
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
        <div className="tls-cards">
          {events.map((ev) => (
            <div
              key={ev.id}
              className="tls-card"
              onClick={() => navigate(`/tls-events/${ev.id}`)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") navigate(`/tls-events/${ev.id}`); }}
              tabIndex={0}
              role="button"
            >
              <div className="tls-card-header">
                <span className="tls-card-sni" title={ev.sni}>{ev.sni}</span>
                <svg className="tls-card-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M9 18l6-6-6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <div className="tls-card-meta">
                <span className="tls-card-time">{formatEventTime(ev.ts_ms)}</span>
                {ev.app && (
                  <>
                    <span className="tls-card-sep" aria-hidden>&middot;</span>
                    <span className="tls-card-app">{ev.app}</span>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      {!loading && !error && events.length === 0 && (
        <div className="events-list-empty-state">
          <div className="events-list-empty-state-icon" aria-hidden>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h2 className="events-list-empty-state-title">No Logs</h2>
          <p className="events-list-empty-state-subtitle">
            When a TLS MITM handshake fails (e.g. due to certificate pinning) or other network-related issues occur, it will appear here.
          </p>
        </div>
      )}
      {confirmingCollect && (
        <div className="confirm-overlay" role="dialog" aria-modal="true">
          <div className="confirm-dialog">
            <p className="confirm-title">Upload logs?</p>
            <p className="confirm-body">
              Endpoint Protection will gather diagnostic logs from this device and securely upload them to Aikido so we can investigate any issues. Continue?
            </p>
            <div className="confirm-actions">
              <button
                type="button"
                className="button-brand button--tertiary button--normal button--rounded"
                onClick={handleCollectCancel}
              >
                Cancel
              </button>
              <button
                type="button"
                className="button-brand button--primary button--normal button--rounded"
                onClick={handleCollectConfirm}
              >
                Upload
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
