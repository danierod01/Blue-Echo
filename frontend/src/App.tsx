import { useState, useRef, useEffect } from "react";
import { Routes, Route, NavLink, useNavigate, useLocation, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Radar, LogOut, ChevronDown } from "lucide-react";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";
import ScanDetail from "@/pages/ScanDetail";
import Login from "@/pages/Login";
import Invite from "@/pages/Invite";
import NotFound from "@/pages/NotFound";
import ProtectedRoute from "@/components/ProtectedRoute";
import { clearStoredApiKey, getStoredApiKey, getMe } from "@/api/client";
import { cn } from "@/lib/utils";

function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "BE";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function UserMenu() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    staleTime: 60_000,
  });
  const name = me?.name ?? "";
  const role = me?.role ?? "";

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  function logout() {
    setOpen(false);
    clearStoredApiKey();
    queryClient.clear();
    navigate("/login", { replace: true });
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-400 hover:text-white transition-colors"
      >
        <div className="w-6 h-6 rounded bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center">
          <span className="text-[9px] font-bold text-white font-data">{initialsOf(name)}</span>
        </div>
        {name && <span className="hidden sm:block max-w-[140px] truncate">{name}</span>}
        <ChevronDown size={11} className={cn("transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-48 bg-[#0d0f1a] border border-white/8 rounded-lg shadow-2xl shadow-black/50 py-1 z-50 animate-[fadeSlideIn_0.15s_ease_forwards]">
          {name && (
            <div className="px-3 py-2 border-b border-white/5">
              <p className="text-sm text-white truncate">{name}</p>
              <p className="text-[10px] text-gray-500">
                Sesión activa{role ? ` · ${role === "admin" ? "Administrador" : "Analista"}` : ""}
              </p>
            </div>
          )}
          <NavLink to="/" end onClick={() => setOpen(false)}
            className={({ isActive }) => cn("flex items-center gap-2 px-3 py-2 text-sm transition-colors", isActive ? "text-white" : "text-gray-400 hover:text-white")}>
            Dashboard
          </NavLink>
          <NavLink to="/history" onClick={() => setOpen(false)}
            className={({ isActive }) => cn("flex items-center gap-2 px-3 py-2 text-sm transition-colors", isActive ? "text-white" : "text-gray-400 hover:text-white")}>
            Historial
          </NavLink>
          <div className="h-px bg-white/5 my-1" />
          <button onClick={logout}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-500 hover:text-red-400 transition-colors">
            <LogOut size={13} />
            Cerrar sesión
          </button>
        </div>
      )}
    </div>
  );
}

function Header() {
  const hasSession = !!getStoredApiKey();

  return (
    <header className="border-b border-white/5 bg-[#08080f]/90 backdrop-blur-sm sticky top-0 z-40">
      <div className="max-w-6xl mx-auto px-6 h-12 flex items-center gap-6">
        <Link to="/" className="flex items-center gap-2 shrink-0">
          <Radar size={18} className="text-blue-400" />
          <span className="font-bold text-sm tracking-tight bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            BlueEcho
          </span>
        </Link>

        {hasSession && (
          <>
            <nav className="flex gap-1">
              {[{ to: "/", label: "Escaneo", end: true }, { to: "/history", label: "Historial" }].map(({ to, label, end }) => (
                <NavLink key={to} to={to} end={end}
                  className={({ isActive }) => cn(
                    "px-3 py-1 text-sm rounded transition-colors",
                    isActive ? "text-white bg-white/8" : "text-gray-500 hover:text-gray-300"
                  )}>
                  {label}
                </NavLink>
              ))}
            </nav>
            <div className="ml-auto">
              <UserMenu />
            </div>
          </>
        )}
      </div>
      {/* Línea de acento inferior */}
      <div className="h-px bg-gradient-to-r from-transparent via-blue-500/30 to-transparent" />
    </header>
  );
}

export default function App() {
  const location = useLocation();
  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      <main className="flex-1 max-w-6xl mx-auto w-full px-6 py-6">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/invite" element={<Invite />} />
          <Route path="/" element={<ProtectedRoute><Dashboard key={location.key} /></ProtectedRoute>} />
          <Route path="/history" element={<ProtectedRoute><History /></ProtectedRoute>} />
          <Route path="/history/:id" element={<ProtectedRoute><ScanDetail /></ProtectedRoute>} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}
