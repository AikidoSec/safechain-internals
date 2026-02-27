import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import { Events } from "@wailsio/runtime";
import { EventsList } from "./pages/EventsList";
import { EventDetail } from "./pages/EventDetail";
// import { daemonStatus } from "./api";
import logoUrl from "../assets/logo.svg";
import "./App.css";



function FocusHandler() {
  const navigate = useNavigate();
  useEffect(() => {
    const unsub = Events.On("focus_event", (ev: { data?: { eventId?: string } }) => {
      const id = ev.data?.eventId;
      if (id) navigate(`/events/${id}`);
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
        <main className="dashboard">
          <AppRoutes />
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
