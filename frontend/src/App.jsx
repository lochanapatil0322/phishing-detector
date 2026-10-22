import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext";
import AppShell from "./components/AppShell";
import AuthLayout from "./components/AuthLayout";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import History from "./pages/History";
import ModelPerformance from "./pages/ModelPerformance";
import HowItWorks from "./pages/HowItWorks";
import Settings from "./pages/Settings";
import ThreatFeed from "./pages/ThreatFeed";
import DomainLookup from "./pages/DomainLookup";

function RequireAuth() {
  const { user, loading } = useAuth();
  if (loading) return <p className="center muted">Loading...</p>;
  return user ? <AppShell /> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />

      <Route element={<AuthLayout />}>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
      </Route>

      <Route element={<RequireAuth />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/history" element={<History />} />
        <Route path="/threat-feed" element={<ThreatFeed />} />
        <Route path="/domain-lookup" element={<DomainLookup />} />
        <Route path="/model" element={<ModelPerformance />} />
        <Route path="/how-it-works" element={<HowItWorks />} />
        <Route path="/settings" element={<Settings />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}