import { useState, useRef, useEffect } from "react";
import { Routes, Route, NavLink, useNavigate, useLocation, Link } from "react-router-dom";
import { Radar, LogOut, LayoutDashboard, Clock, ChevronDown } from "lucide-react";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";
import ScanDetail from "@/pages/ScanDetail";
import Login from "@/pages/Login";
import ProtectedRoute from "@/components/ProtectedRoute";
import { clearStoredApiKey, getStoredApiKey } from "@/api/client";
import { cn } from "@/lib/utils";

function UserMenu() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  function logout() {
    setOpen(false);
    clearStoredApiKey();
    navigate("/login", { replace: true });
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm transition-all duration-200",
          open
            ? "border-blue-500/40 bg-blue-500/10 text-blue-300"
            : "border-gray-700/60 bg-gray-800/50 text-gray-400 hover:border-gray-600 hover:text-gray-200"
        )}
      >
        <div className="w-5 h-5 rounded-full bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
          <span className="text-[9px] font-bold text-white">BE</span>
        </div>
        <ChevronDown
          size={12}
          className={cn("transition-transform duration-200", open && "rotate-180")}
        />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-52 rounded-xl border border-gray-700/60 bg-gray-900/95 backdrop-blur-sm shadow-2xl shadow-black/60 py-1.5 z-50 animate-[fadeSlideIn_0.15s_ease_forwards]">
          <div className="px-4 py-2 border-b border-gray-800 mb-1">
            <p className="text-xs text-gray-500">BlueEcho</p>
            <p className="text-xs font-medium text-gray-300">Panel de análisis</p>
          </div>

          <NavLink
            to="/"
            end
            onClick={() => setOpen(false)}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 px-4 py-2 text-sm transition",
                isActive
                  ? "text-blue-300 bg-blue-500/10"
                  : "text-gray-300 hover:bg-gray-800 hover:text-white"
              )
            }
          >
            <LayoutDashboard size={14} />
            Dashboard
          </NavLink>

          <NavLink
            to="/history"
            onClick={() => setOpen(false)}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 px-4 py-2 text-sm transition",
                isActive
                  ? "text-blue-300 bg-blue-500/10"
                  : "text-gray-300 hover:bg-gray-800 hover:text-white"
              )
            }
          >
            <Clock size={14} />
            Historial
          </NavLink>

          <div className="border-t border-gray-800 mt-1 pt-1">
            <button
              onClick={logout}
              className="w-full flex items-center gap-2.5 px-4 py-2 text-sm text-gray-500 hover:text-red-400 hover:bg-gray-800 transition"
            >
              <LogOut size={14} />
              Cerrar sesión
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Header() {
  const hasSession = !!getStoredApiKey();

  return (
    <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-[#0a0a12]/80 backdrop-blur-md">
      <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-2.5 shrink-0 group">
          <div className="relative">
            <Radar
              size={22}
              className="text-blue-400 group-hover:text-cyan-400 transition-colors duration-300"
            />
            {/* Glow pulse */}
            <div className="absolute inset-0 rounded-full bg-blue-500/20 blur-md animate-pulse opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
          </div>
          <span className="font-bold text-lg bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent tracking-tight">
            BlueEcho
          </span>
        </Link>

        {hasSession && (
          <>
            {/* Tabs con fondo */}
            <nav className="flex items-center bg-gray-800/40 rounded-lg p-0.5 border border-gray-700/30 ml-2">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-all duration-200",
                    isActive
                      ? "bg-gray-700/80 text-white shadow-sm"
                      : "text-gray-400 hover:text-gray-200"
                  )
                }
              >
                <LayoutDashboard size={13} />
                <span className="hidden sm:inline">Dashboard</span>
              </NavLink>
              <NavLink
                to="/history"
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-all duration-200",
                    isActive
                      ? "bg-gray-700/80 text-white shadow-sm"
                      : "text-gray-400 hover:text-gray-200"
                  )
                }
              >
                <Clock size={13} />
                <span className="hidden sm:inline">Historial</span>
              </NavLink>
            </nav>

            <div className="ml-auto">
              <UserMenu />
            </div>
          </>
        )}
      </div>
    </header>
  );
}

export default function App() {
  const location = useLocation();

  return (
    <div className="min-h-screen flex flex-col bg-[#0a0a12]">
      {/* Aurora sutil en la parte superior */}
      <div
        className="pointer-events-none fixed inset-0 z-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 40% at 50% -10%, rgba(59,130,246,0.07) 0%, transparent 70%)",
        }}
      />

      <Header />

      <main className="relative z-10 flex-1 max-w-6xl mx-auto w-full px-4 py-8">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard key={location.key} />
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

      <footer className="relative z-10 border-t border-white/[0.04] text-center text-xs text-gray-700 py-3">
        BlueEcho · Máster en Ciberseguridad 2025-2026
      </footer>
    </div>
  );
}
