import { Routes, Route, NavLink, useNavigate } from "react-router-dom";
import { ShieldAlert, LogOut } from "lucide-react";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";
import ScanDetail from "@/pages/ScanDetail";
import Login from "@/pages/Login";
import ProtectedRoute from "@/components/ProtectedRoute";
import { clearStoredApiKey, getStoredApiKey } from "@/api/client";

function Header() {
  const navigate = useNavigate();
  const hasSession = !!getStoredApiKey();

  function logout() {
    clearStoredApiKey();
    navigate("/login", { replace: true });
  }

  return (
    <header className="border-b border-gray-800 bg-gray-900">
      <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-6">
        <div className="flex items-center gap-2 text-blue-400 font-bold text-lg">
          <ShieldAlert size={22} />
          Blue-Echo
        </div>

        {hasSession && (
          <>
            <nav className="flex gap-4 text-sm flex-1">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  isActive ? "text-white font-medium" : "text-gray-400 hover:text-white"
                }
              >
                Dashboard
              </NavLink>
              <NavLink
                to="/history"
                className={({ isActive }) =>
                  isActive ? "text-white font-medium" : "text-gray-400 hover:text-white"
                }
              >
                Historial
              </NavLink>
            </nav>

            <button
              onClick={logout}
              className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-red-400 transition ml-auto"
            >
              <LogOut size={14} />
              Cerrar sesión
            </button>
          </>
        )}
      </div>
    </header>
  );
}

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1 max-w-6xl mx-auto w-full px-4 py-8">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/history"
            element={
              <ProtectedRoute>
                <History />
              </ProtectedRoute>
            }
          />
          <Route
            path="/history/:id"
            element={
              <ProtectedRoute>
                <ScanDetail />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>

      <footer className="border-t border-gray-800 text-center text-xs text-gray-600 py-3">
        Blue-Echo · Máster en Ciberseguridad 2025-2026
      </footer>
    </div>
  );
}
