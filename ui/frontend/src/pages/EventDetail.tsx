import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import type { BlockEvent, BlockReason } from "../types";
import { getEvent, requestAccess } from "../api";
import { Events } from "@wailsio/runtime";
import { BLOCK_REASON_LABEL, getToolIcon } from "../constants";
import { formatEventTime, isConnectionError } from "../utils";

const BLOCK_REASON_INFO: Record<BlockReason, { title: string; description: string }> = {
  malware: {
    title: "Malware detected",
    description: "This package was blocked because it was flagged as malware.",
  },
  rejected: {
    title: "Package blocked",
    description: "This package has been explicitly blocked by policy.",
  },
  block_all: {
    title: "All Installs Blocked",
    description: "All package installations are currently blocked by policy.",
  },
  request_install: {
    title: "Request Access",
    description: "You need to request access to install the following package. After requesting access, an admin of your Aikido workspace will be able to approve or reject this package.",
  },
  new_package: {
    title: "Package Too New",
    description: "This package was blocked because it was published too recently and hasn't met the minimum package age policy. New packages need time to be vetted by the community before they can be installed.",
  },
};

function EventInfo({ event }: { event: BlockEvent }) {
  return (
    <dl className="event-info">
      <div className="event-info-row">
        <dt>Package</dt>
        <dd className="event-info-package">
          <img
            src={getToolIcon(event.artifact.product)}
            alt={event.artifact.product}
            className="event-info-icon"
          />
          {event.artifact.display_name ?? event.artifact.identifier}
          {event.count !== undefined && event.count > 1 && (
            <span className="event-count-badge" aria-label={`${event.count} blocked events`}>
              x{event.count}
            </span>
          )}
        </dd>
      </div>
      {event.artifact.version && (
        <div className="event-info-row">
          <dt>Version</dt>
          <dd>{event.artifact.version}</dd>
        </div>
      )}
      <div className="event-info-row">
        <dt>Blocked at</dt>
        <dd>{formatEventTime(event.ts_ms)}</dd>
      </div>
      <div className="event-info-row">
        <dt>Reason</dt>
        <dd>
          <span className={`reason-badge reason-badge--${event.block_reason}`}>
            {BLOCK_REASON_LABEL[event.block_reason] ?? event.block_reason}
          </span>
        </dd>
      </div>
    </dl>
  );
}

export function EventDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [event, setEvent] = useState<BlockEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requesting, setRequesting] = useState(false);

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

  const [requestSent, setRequestSent] = useState(false);

  // Listen for live permission pushes from daemon heartbeat
  useEffect(() => {
    const unsub = Events.On("permissions_updated", (ev: unknown) => {
      loadEvent();
    });
    return () => { unsub(); };
  }, [loadEvent]);

  const handleRequestAccess = async () => {
    if (!id) return;
    setRequesting(true);
    setError(null);
    try {
      await requestAccess(id);
      setEvent((prev) => (prev ? { ...prev, status: "request_pending" } : null));
      setRequestSent(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRequesting(false);
    }
  };

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

  // Access requests are currently permitted for all blocked events by default
  const canRequest = true;
  const info = BLOCK_REASON_INFO[event.block_reason];

  if (event.status === "request_approved") {
    return (
      <div className="event-detail event-detail--full">
        <div className="request-success">
          <div className="request-success-body">
            <div className="request-success-icon request-approved-icon" aria-hidden>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h2>Request Approved</h2>
            <p className="subtitle">
              Your access request for <strong>{event.artifact.display_name ?? event.artifact.identifier}</strong> has been approved. You can now install this package.
            </p>
          </div>
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--primary button--normal button--rounded"
              onClick={() => navigate("/events")}
            >
              Back to list
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (event.status === "request_rejected") {
    return (
      <div className="event-detail event-detail--full">
        <div className="request-success">
          <div className="request-success-body">
            <div className="request-success-icon request-rejected-icon" aria-hidden>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h2>Request Rejected</h2>
            <p className="subtitle">
              Your access request for <strong>{event.artifact.display_name ?? event.artifact.identifier}</strong> has been rejected. Contact your workspace admin for more details.
            </p>
          </div>
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--primary button--normal button--rounded"
              onClick={() => navigate("/events")}
            >
              Back to list
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (requestSent || event.status === "request_pending") {
    return (
      <div className="event-detail event-detail--full">
        <div className="request-success">
          <div className="request-success-body">
            <div className="request-success-icon" aria-hidden>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M22 4L12 14.01l-3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <h2>Request Sent</h2>
            <p className="subtitle">
              Your access request for <strong>{event.artifact.display_name ?? event.artifact.identifier}</strong> has been submitted.
            </p>
          </div>
          <div className="request-access-actions">
            <button
              type="button"
              className="button-brand button--primary button--normal button--rounded"
              onClick={() => navigate("/events")}
            >
              Back to list
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="event-detail event-detail--full">
      <div className="request-access-section">
        <div className="request-access-section-body">
          <h2>{info?.title ?? "Access not available"}</h2>
          <p className="subtitle">
            {info?.description ?? "Access cannot be requested for this package."}
          </p>
          <EventInfo event={event} />
          {error && <p className="error">{error}</p>}
        </div>

        <div className="request-access-actions">
          <button
            type="button"
            className="button-brand button--tertiary button--normal button--rounded"
            onClick={() => navigate("/events")}
          >
            {canRequest ? "Back" : "Back to list"}
          </button>
          {canRequest && (
            <button
              type="button"
              className="button-brand button--primary button--normal button--rounded"
              onClick={handleRequestAccess}
              disabled={requesting}
            >
              {requesting ? "Requesting…" : "Request Access"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
