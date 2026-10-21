import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext";
import Navbar from "./components/Navbar";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Scan from "./pages/Scan";
import History from "./pages/History";
import Dashboard from "./pages/Dashboard";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <p className="center muted">Loading...</p>;
  return user ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <>
      <Navbar />
      <main className="container">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/" element={<Protected><Scan /></Protected>} />
          <Route path="/history" element={<Protected><History /></Protected>} />
          <Route path="/dashboard" element={<Protected><Dashboard /></Protected>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  );
}