import { useEffect, useState } from "react";
import { Events } from "@wailsio/runtime";
import type { BlockEvent } from "../types";
import { BLOCK_REASON_LABEL, getToolIcon } from "../constants";
import { openDashboardToEvent, closeTrayNotification } from "../api";
import logoUrl from "../../assets/logo.svg";

export function TrayNotification() {
  const [event, setEvent] = useState<BlockEvent | null>(null);

  useEffect(() => {
    const unsub = Events.On("blocked", (ev: unknown) => {
      const payload = (ev as { data?: BlockEvent }).data;
      if (payload) setEvent(payload);
    });
    return () => {
      unsub();
    };
  }, []);

  if (!event) {
    return (
      <div className="tray-notif-root">
        <div className="tray-notif">
          <div className="tray-notif__empty">
            <img src={logoUrl} alt="Aikido" className="tray-notif__logo" />
            <p className="tray-notif__empty-text">No recent events</p>
            <button
              type="button"
              className="tray-notif__action tray-notif__action--dismiss"
              onClick={() => {
                closeTrayNotification();
              }}
            >
              Close</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="tray-notif-root">
      <div className="tray-notif">
        <div className="tray-notif__header">
          <img src={logoUrl} alt="Aikido" className="tray-notif__logo" />
          <span className="tray-notif__title">Event Blocked</span>
        </div>
        <div className="tray-notif__body">
          <img
            src={getToolIcon(event.artifact.product)}
            alt={event.artifact.product}
            className="tray-notif__icon"
          />
          <div className="tray-notif__info">
            <span className="tray-notif__package">
              {event.artifact.display_name || event.artifact.identifier}
            </span>
            <span className={`reason-badge reason-badge--${event.block_reason}`}>
              {BLOCK_REASON_LABEL[event.block_reason] ?? event.block_reason}
            </span>
          </div>
        </div>
        <div className="tray-notif__footer">
          <button
            type="button"
            className="tray-notif__action tray-notif__action--dismiss"
            onClick={() => {
              closeTrayNotification();
            }}
          >
            Dismiss
          </button>
          <button
            type="button"
            className="tray-notif__action tray-notif__action--primary"
            onClick={() => {
              openDashboardToEvent(event.id, "block");
            }}
          >
            Open Dashboard
          </button>
        </div>
      </div>
    </div>
  );
}
