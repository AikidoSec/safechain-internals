import { useEffect, useState } from "react";
import { HashRouter, Routes, Route, NavLink, useNavigate, Outlet, useLocation, useOutletContext } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { EventsList } from "./pages/EventsList";
import { EventDetail } from "./pages/EventDetail";
import { TlsEventsList } from "./pages/TlsEventsList";
import { TlsEventDetail } from "./pages/TlsEventDetail";
import { ProtectedEcosystems } from "./pages/ProtectedEcosystems";
import { InstallPage } from "./pages/InstallPage";
import { getVersion, setupCheck, setupStart } from "./api";
import logoUrl from "../assets/logo.svg";
import "./App.css";

export type DashboardContext = {
  setupRequired: boolean;
  onStartSetup: () => void;
};

export function useDashboardContext(): DashboardContext {
  return useOutletContext<DashboardContext>();
}

function FocusHandler() {
  const navigate = useNavigate();
  useEffect(() => {
    const unsub = Events.On("focus_event", (ev: { data?: { eventId?: string; eventType?: string } }) => {
      if (ev.data?.eventId === "") {
        navigate("/");
        return;
      }
      const id = ev.data?.eventId;
      if (!id) return;
      if (ev.data?.eventType === "tls") {
        navigate(`/tls-events/${id}`);
      } else {
        navigate(`/events/${id}`);
      }
    });
    return () => {
      unsub();
    };
  }, [navigate]);
  return null;
}

function DashboardLayout() {
  const location = useLocation();
  const [version, setVersion] = useState("");
  const [setupRequired, setSetupRequired] = useState(false);
  useEffect(() => {
    getVersion().then(setVersion).catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;
    setupCheck()
      .then((ok) => {
        if (!cancelled) setSetupRequired(!ok);
      })
      .catch(() => {});
    const unsub = Events.On("setup_state", (ev: { data?: { setupRequired?: boolean } }) => {
      if (typeof ev.data?.setupRequired === "boolean") {
        setSetupRequired(ev.data.setupRequired);
      }
    });
    return () => {
      cancelled = true;
      unsub();
    };
  }, []);

  const onStartSetup = () => {
    setupStart().catch(() => {});
  };

  const eventsTabActive = location.pathname === "/" || location.pathname.startsWith("/events");

  return (
    <div className="container">
      <header className="app-header">
        <img src={logoUrl} alt="Aikido" className="app-logo-img" />
        <div className="app-header-right">
          {setupRequired && (
            <button
              type="button"
              className="app-setup-required-btn"
              onClick={onStartSetup}
            >
              <span className="app-setup-required-btn__icon" aria-hidden>⚠</span>
              System Setup Required…
            </button>
          )}
          {version && <span className="app-version">v{version}</span>}
        </div>
      </header>
      <nav className="app-tabs">
        <NavLink to="/events" className={() => `app-tab${eventsTabActive ? " app-tab--active" : ""}`}>
          Events
        </NavLink>
        <NavLink to="/tls-events" className={({ isActive }) => `app-tab${isActive ? " app-tab--active" : ""}`}>
          Logs
        </NavLink>
        <NavLink
          to="/protected-ecosystems"
          className={({ isActive }) => `app-tab${isActive ? " app-tab--active" : ""}`}
        >
          Protected Ecosystems
        </NavLink>
      </nav>
      <main className="dashboard">
        <FocusHandler />
        <Outlet context={{ setupRequired, onStartSetup } satisfies DashboardContext} />
      </main>
    </div>
  );
}

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/install" element={<InstallPage />} />
        <Route element={<DashboardLayout />}>
          <Route path="/" element={<EventsList />} />
          <Route path="/events" element={<EventsList />} />
          <Route path="/events/:id" element={<EventDetail />} />
          <Route path="/tls-events" element={<TlsEventsList />} />
          <Route path="/tls-events/:id" element={<TlsEventDetail />} />
          <Route path="/protected-ecosystems" element={<ProtectedEcosystems />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;
