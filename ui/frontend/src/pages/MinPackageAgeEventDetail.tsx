import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import type { MinPackageAgeEvent } from "../types";
import { getMinPackageAgeEvent } from "../api";
import { Events } from "@wailsio/runtime";
import { formatEventTime, isConnectionError } from "../utils";

export function MinPackageAgeEventDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [event, setEvent] = useState<MinPackageAgeEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadEvent = useCallback(() => {
    if (!id) return;
    setLoading(true);
    setError(null);
    getMinPackageAgeEvent(id)
      .then(setEvent)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    loadEvent();
  }, [loadEvent]);

  useEffect(() => {
    const unsub = Events.On("min_package_age", (ev: unknown) => {
      const payload = (ev as { data?: MinPackageAgeEvent }).data;
      if (payload && payload.id === id) {
        setEvent(payload);
      }
    });
    return () => {
      unsub();
    };
  }, [id]);

  if (loading && !event) return <p className="loading">Loading event…</p>;

  if (error && !event) {
    const connectionFailed = isConnectionError(error);
    return (
      <div className="event-detail">
        <div className="event-detail-fail">
          <h2>
            {connectionFailed ? "Can't connect to Aikido Endpoint Protection" : "Something went wrong"}
          </h2>
          <p className="event-detail-fail-subtitle">
            {connectionFailed
              ? "The app couldn't reach the Aikido Endpoint Protection service. Make sure it's running, then try again."
              : "We couldn't load this log entry. You can try again or go back to the list."}
          </p>
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--tertiary button--normal button--rounded"
              onClick={() => navigate("/tls-events")}
            >
              Back to list
            </button>
            <button
              type="button"
              className="button-brand button--primary button--normal button--rounded"
              onClick={loadEvent}
              disabled={loading}
            >
              {loading ? "Retrying…" : "Try again"}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!event) return <p className="loading">Event not found.</p>;

  return (
    <div className="event-detail event-detail--full">
      <div className="tls-detail-section">
        <button
          type="button"
          className="tls-back-link"
          onClick={() => navigate("/tls-events")}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M19 12H5M12 19l-7-7 7-7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          Logs
        </button>

        <div className="tls-detail-header">
          <div className="tls-detail-badge">Minimum Package Age</div>
          <h2 className="tls-detail-sni">{event.title}</h2>
          <p className="tls-detail-subtitle">{event.message}</p>
        </div>

        <dl className="tls-detail-info">
          <div className="tls-detail-info-row">
            <dt>Ecosystem</dt>
            <dd>{event.ecosystem}</dd>
          </div>
          <div className="tls-detail-info-row">
            <dt>Occurred at</dt>
            <dd>{formatEventTime(event.ts_ms)}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
