import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import type { BlockedEvent } from "../types";
import { getEvent, requestAccess } from "../api";

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

export function EventDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [event, setEvent] = useState<BlockedEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requesting, setRequesting] = useState(false);
  const [email, setEmail] = useState("");

  const loadEvent = useCallback(() => {
    if (!id) return;
    setLoading(true);
    setError(null);
    getEvent(id)
      .then(setEvent)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    loadEvent();
  }, [loadEvent]);

  const handleRequestAccess = async () => {
    if (!id) return;
    setRequesting(true);
    setError(null);
    try {
      await requestAccess(id, email.trim() || "Access requested");
      setEvent((prev) => (prev ? { ...prev, status: "request_pending" } : null));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRequesting(false);
    }
  };

  const handleCancel = () => {
    navigate("/events");
  };

  if (loading && !event) return <p className="loading">Loading event…</p>;

  if (error && !event) {
    const connectionFailed = isConnectionError(error);
    return (
      <div className="event-detail">
        <button type="button" className="back" onClick={() => navigate("/events")}>
          ← Back to list
        </button>
        <div className="event-detail-fail">
          <h2>
            {connectionFailed ? "Can't connect to SafeChain" : "Something went wrong"}
          </h2>
          <p className="event-detail-fail-subtitle">
            {connectionFailed
              ? "The app couldn't reach the SafeChain service. Make sure it's running, then try again."
              : "We couldn't load this event. You can try again or go back to the list."}
          </p>
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--tertiary button--normal button--rounded"
              onClick={() => navigate("/events")}
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
    <div className="event-detail">
      <button type="button" className="back" onClick={() => navigate("/events")}>
        ← Back to list
      </button>

      {event.bypass_enabled && (
        <div className="request-access-section">
          <h2>Request Access</h2>
          <p className="subtitle">
            You need to request access to install the following package.
          </p>
          <div className="field">
            <div className="field-readonly">{event.identifier}</div>
          </div>
          <div className="field">
            <label>Email</label>
            <input
              type="email"
              className={`input-field${error ? " input-field--error" : ""}`}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="email@company.com"
            />
          </div>
          {error && <p className="error">{error}</p>}
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--tertiary button--normal button--rounded"
              onClick={handleCancel}
            >
              Cancel
            </button>
            <button
              type="button"
              className="button-brand button--primary button--normal button--rounded"
              onClick={handleRequestAccess}
              disabled={requesting}
            >
              {requesting ? "Requesting…" : "Request Access"}
            </button>
          </div>
        </div>
      )}

      {!event.bypass_enabled && (
        <div className="request-access-section no-bypass-section">
          <h2>Access not available</h2>
          <p className="subtitle">
            Bypass is not enabled for this event. You cannot request access for the following package.
          </p>
          <div className="field">
            <div className="field-readonly">{event.identifier}</div>
          </div>
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--tertiary button--normal button--rounded"
              onClick={handleCancel}
            >
              Back to list
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
