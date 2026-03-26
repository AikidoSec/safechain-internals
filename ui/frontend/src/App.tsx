import { useEffect } from "react";
import { BrowserRouter, Routes, Route, NavLink, useNavigate } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { EventsList } from "./pages/EventsList";
import { EventDetail } from "./pages/EventDetail";
import { TlsEventsList } from "./pages/TlsEventsList";
import { TlsEventDetail } from "./pages/TlsEventDetail";
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

function AppRoutes() {
  return (
    <>
      <FocusHandler />
      <Routes>
        <Route path="/" element={<EventsList />} />
        <Route path="/events" element={<EventsList />} />
        <Route path="/events/:id" element={<EventDetail />} />
        <Route path="/tls-events" element={<TlsEventsList />} />
        <Route path="/tls-events/:id" element={<TlsEventDetail />} />
      </Routes>
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      <div className="container">
        <header className="app-header">
          <img src={logoUrl} alt="Aikido" className="app-logo-img" />
        </header>
        <nav className="app-tabs">
          <NavLink to="/events" className={({ isActive }) => `app-tab${isActive || location.pathname === "/" ? " app-tab--active" : ""}`}>
            Blocked Events
          </NavLink>
          <NavLink to="/tls-events" className={({ isActive }) => `app-tab${isActive ? " app-tab--active" : ""}`}>
            TLS Failures
          </NavLink>
        </nav>
        <main className="dashboard">
          <AppRoutes />
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
