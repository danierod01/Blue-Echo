import { Routes, Route, NavLink } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-gray-800 bg-gray-900">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-6">
          <div className="flex items-center gap-2 text-blue-400 font-bold text-lg">
            <ShieldAlert size={22} />
            Blue-Echo
          </div>
          <nav className="flex gap-4 text-sm">
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
        </div>
      </header>

      <main className="flex-1 max-w-6xl mx-auto w-full px-4 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>

      <footer className="border-t border-gray-800 text-center text-xs text-gray-600 py-3">
        Blue-Echo · Máster en Ciberseguridad 2025-2026
      </footer>
    </div>
  );
}
