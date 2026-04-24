import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import type { LogEvent, MinPackageAgeEvent, TlsTerminationFailedEvent } from "../types";
import { Events } from "@wailsio/runtime";
import { listMinPackageAgeEvents, listTlsEvents,collectLogs } from "../api";
import { formatEventTime, isConnectionError } from "../utils";

function compareDescByTime(a: LogEvent, b: LogEvent) {
  return b.ts_ms - a.ts_ms;
}

function upsertLogEvent(events: LogEvent[], nextEvent: LogEvent): LogEvent[] {
  const filtered = events.filter((event) => !(event.type === nextEvent.type && event.id === nextEvent.id));
  return [nextEvent, ...filtered].sort(compareDescByTime);
}

type CollectStatus = "idle" | "success" | "error";

export function TlsEventsList() {
  const navigate = useNavigate();
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [collecting, setCollecting] = useState(false);
  const [collectStatus, setCollectStatus] = useState<CollectStatus>("idle");
  const [confirmingCollect, setConfirmingCollect] = useState(false);

  const handleCollectLogsClick = useCallback(() => {
    setCollectStatus("idle");
    setConfirmingCollect(true);
  }, []);

  const handleCollectCancel = useCallback(() => {
    setConfirmingCollect(false);
  }, []);

  const handleCollectConfirm = useCallback(async () => {
    setConfirmingCollect(false);
    setCollecting(true);
    setCollectStatus("idle");
    try {
      await collectLogs();
      setCollectStatus("success");
    } catch {
      setCollectStatus("error");
    } finally {
      setCollecting(false);
    }
  }, []);

  useEffect(() => {
    if (collectStatus === "idle") return;
    const id = window.setTimeout(() => setCollectStatus("idle"), 4000);
    return () => window.clearTimeout(id);
  }, [collectStatus]);

  let uploadButtonLabel = "Upload Logs";
  if (collecting) uploadButtonLabel = "Uploading…";
  else if (collectStatus === "success") uploadButtonLabel = "Upload successful";
  else if (collectStatus === "error") uploadButtonLabel = "Upload failed";

  const uploadButtonClass = [
    "button-brand",
    "button--primary",
    "button--normal",
    "button--rounded",
    collectStatus === "success" ? "button--success" : "",
    collectStatus === "error" ? "button--danger" : "",
  ]
    .filter(Boolean)
    .join(" ");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [tlsEvents, minPackageAgeEvents] = await Promise.all([
        listTlsEvents(50),
        listMinPackageAgeEvents(50),
      ]);
      const combined: LogEvent[] = [
        ...(tlsEvents ?? []).map((event) => ({ ...event, type: "tls" as const })),
        ...(minPackageAgeEvents ?? []).map((event) => ({ ...event, type: "min_package_age" as const })),
      ].sort(compareDescByTime);
      setEvents(combined);
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
      if (payload) {
        setEvents((prev) => upsertLogEvent(prev, { ...payload, type: "tls" }));
      }
    });
    return () => {
      unsub();
    };
  }, []);

  useEffect(() => {
    const unsub = Events.On("min_package_age", (ev: unknown) => {
      const payload = (ev as { data?: MinPackageAgeEvent }).data;
      if (payload) {
        setEvents((prev) => upsertLogEvent(prev, { ...payload, type: "min_package_age" }));
      }
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
          className={uploadButtonClass}
          onClick={handleCollectLogsClick}
          disabled={collecting}
        >
          {uploadButtonLabel}
        </button>
      </div>
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
              onClick={() => navigate(ev.type === "tls" ? `/tls-events/${ev.id}` : `/min-package-age-events/${ev.id}`)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  navigate(ev.type === "tls" ? `/tls-events/${ev.id}` : `/min-package-age-events/${ev.id}`);
                }
              }}
              tabIndex={0}
              role="button"
            >
              <div className="tls-card-header">
                <span
                  className="tls-card-sni"
                  title={ev.type === "tls" ? ev.sni : ev.title}
                >
                  {ev.type === "tls" ? ev.sni : ev.title}
                </span>
                <svg className="tls-card-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M9 18l6-6-6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <div className="tls-card-meta">
                <span className="tls-card-time">{formatEventTime(ev.ts_ms)}</span>
                {ev.type === "tls" && ev.app && (
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
            When a TLS MITM handshake fails, or when Aikido suppresses versions that are too new under the minimum package age policy, it will appear here.
          </p>
        </div>
      )}
      {confirmingCollect && (
        <div className="confirm-overlay" role="dialog" aria-modal="true">
          <div className="confirm-dialog">
            <p className="confirm-title">Upload logs?</p>
            <p className="confirm-body">
              Endpoint Protection will gather diagnostic logs from this device and securely upload them to Aikido. Continue?
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
