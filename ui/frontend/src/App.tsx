import { useEffect, useState } from "react";
import { HashRouter, Routes, Route, NavLink, useNavigate, Outlet, useLocation } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { EventsList } from "./pages/EventsList";
import { EventDetail } from "./pages/EventDetail";
import { TlsEventsList } from "./pages/TlsEventsList";
import { TlsEventDetail } from "./pages/TlsEventDetail";
import { MinPackageAgeEventDetail } from "./pages/MinPackageAgeEventDetail";
import { ProtectedEcosystems } from "./pages/ProtectedEcosystems";
import { InstallPage } from "./pages/InstallPage";
import { getVersion } from "./api";
import logoUrl from "../assets/logo.svg";
import "./App.css";

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
  useEffect(() => {
    getVersion().then(setVersion).catch(() => {});
  }, []);

  const eventsTabActive = location.pathname === "/" || location.pathname.startsWith("/events");
  const logsTabActive = location.pathname.startsWith("/tls-events") || location.pathname.startsWith("/min-package-age-events");

  return (
    <div className="container">
      <header className="app-header">
        <img src={logoUrl} alt="Aikido" className="app-logo-img" />
        {version && <span className="app-version">v{version}</span>}
      </header>
      <nav className="app-tabs">
        <NavLink to="/events" className={() => `app-tab${eventsTabActive ? " app-tab--active" : ""}`}>
          Events
        </NavLink>
        <NavLink to="/tls-events" className={() => `app-tab${logsTabActive ? " app-tab--active" : ""}`}>
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
        <Outlet />
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
          <Route path="/min-package-age-events/:id" element={<MinPackageAgeEventDetail />} />
          <Route path="/protected-ecosystems" element={<ProtectedEcosystems />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;
