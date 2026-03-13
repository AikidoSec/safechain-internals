import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import type { BlockEvent, BlockReason } from "../types";
import { getEvent, requestAccess } from "../api";
import { getToolIcon } from "../constants";
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
    title: "All installs blocked",
    description: "All package installations are currently blocked by policy.",
  },
  request_install: {
    title: "Request Access",
    description: "You need to request access to install the following package.",
  },
};

const BLOCK_REASON_LABEL: Record<BlockReason, string> = {
  malware: "Malware",
  rejected: "Rejected by policy",
  block_all: "All installs blocked",
  request_install: "Approval required",
};

const RESULT_ICONS = {
  success: (
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M22 11.08V12a10 10 0 11-5.93-9.14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M22 4L12 14.01l-3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  failure: (
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5"/>
      <path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
};

function ResultScreen({ variant, title, subtitle, actions }: {
  variant: "success" | "failure";
  title: string;
  subtitle: React.ReactNode;
  actions: React.ReactNode;
}) {
  return (
    <div className="event-detail event-detail--full">
      <div className="request-result">
        <div className="request-result-body">
          <div className={`request-result-icon request-result-icon--${variant}`} aria-hidden>
            {RESULT_ICONS[variant]}
          </div>
          <h2>{title}</h2>
          <p className="subtitle">{subtitle}</p>
        </div>
        <div className="request-access-actions">
          {actions}
        </div>
      </div>
    </div>
  );
}

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
  const [requestSent, setRequestSent] = useState(false);
  const [requestFailed, setRequestFailed] = useState(false);

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
    setRequestFailed(false);
    try {
      const updated = await requestAccess(id);
      setEvent(updated);
      setRequestSent(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setRequestFailed(true);
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
            {connectionFailed ? "Can't connect to Aikido Endpoint" : "Something went wrong"}
          </h2>
          <p className="event-detail-fail-subtitle">
            {connectionFailed
              ? "The app couldn't reach the Aikido Endpoint service. Make sure it's running, then try again."
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

  const packageLabel = event.artifact.display_name ?? event.artifact.identifier;

  if (requestFailed && error) {
    return (
      <ResultScreen
        variant="failure"
        title="Request failed"
        subtitle={<>We couldn't submit your access request for <strong>{packageLabel}</strong>. Please try again.</>}
        actions={<>
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
            onClick={handleRequestAccess}
            disabled={requesting}
          >
            {requesting ? "Requesting…" : "Try again"}
          </button>
        </>}
      />
    );
  }

  if (requestSent || event.status === "request_pending") {
    return (
      <ResultScreen
        variant="success"
        title="Request sent"
        subtitle={<>Your access request for <strong>{packageLabel}</strong> has been submitted.</>}
        actions={
          <button
            type="button"
            className="button-brand button--primary button--normal button--rounded"
            onClick={() => navigate("/events")}
          >
            Back to list
          </button>
        }
      />
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
        </div>

        <div className="request-access-actions">
          <button
            type="button"
            className="button-brand button--tertiary button--normal button--rounded"
            onClick={() => navigate("/events")}
          >
            {canRequest ? "Cancel" : "Back to list"}
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
