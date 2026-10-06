import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, UserPlus, RefreshCw, Copy, Check, Loader2, Lock } from "lucide-react";
import {
  getMe, adminListTokens, adminRevokeToken, adminCreateToken,
  type TokenInfo,
} from "@/api/client";
import { useToast } from "@/components/Toast";
import { cn } from "@/lib/utils";

/**
 * Panel de administración — SOLO para sesiones con rol admin.
 * La autorización la hace el backend contra la X-API-Key de la sesión (no el
 * ADMIN_SECRET): aquí un admin lista, crea y revoca tokens de acceso.
 */
export default function AdminPanel() {
  const { toast } = useToast();
  const me = useQuery({ queryKey: ["me"], queryFn: getMe });
  const isAdmin = me.data?.role === "admin";

  const [tokens, setTokens] = useState<TokenInfo[] | null>(null);
  const [loadingList, setLoadingList] = useState(false);
  const [listError, setListError] = useState<string | null>(null);

  // Formulario de creación
  const [label, setLabel] = useState("");
  const [role, setRole] = useState("analyst");
  const [expiresDays, setExpiresDays] = useState("");
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function loadTokens() {
    setLoadingList(true);
    setListError(null);
    try {
      setTokens(await adminListTokens());
    } catch (e) {
      setListError(e instanceof Error ? e.message : "Error listando tokens.");
    } finally {
      setLoadingList(false);
    }
  }

  useEffect(() => {
    if (isAdmin) loadTokens();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setCreated(null);
    try {
      const res = await adminCreateToken({
        label: label.trim(),
        role,
        expiresInDays: expiresDays ? Number(expiresDays) : null,
      });
      setCreated(res.token);
      setLabel("");
      setExpiresDays("");
      toast("Token creado.", "success");
      await loadTokens();
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo crear el token.", "error");
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(id: number) {
    try {
      await adminRevokeToken(id);
      toast("Token revocado.", "success");
      await loadTokens();
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo revocar el token.", "error");
    }
  }

  // Acceso denegado para no-admins.
  if (me.isLoading) {
    return <div className="flex justify-center py-16 text-gray-500"><Loader2 size={22} className="animate-spin" /></div>;
  }
  if (!isAdmin) {
    return (
      <div className="soc-panel p-8 max-w-md mx-auto text-center">
        <Lock size={28} className="text-slate-500 mx-auto mb-3" />
        <h1 className="text-lg font-semibold text-white mb-1">Acceso restringido</h1>
        <p className="text-sm text-slate-400">
          Esta sección es solo para administradores. Tu sesión no tiene rol admin.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck size={22} className="text-accent" />
          Administración
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Gestión de tokens de acceso. Autorizado por tu sesión de administrador.
        </p>
      </div>

      {/* Crear token */}
      <div className="soc-panel p-5">
        <div className="flex items-center gap-2 mb-3">
          <UserPlus size={15} className="text-accent" />
          <span className="soc-label">Crear token de acceso</span>
        </div>
        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div className="sm:col-span-2">
            <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Nombre / identificador</label>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              required
              placeholder="p. ej. Jose Manuel"
              className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-accent/60 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Rol</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-slate-900 px-3 py-2 text-sm text-white focus:border-accent/60 focus:outline-none"
            >
              <option value="analyst">Analista</option>
              <option value="admin">Administrador</option>
            </select>
          </div>
          <div>
            <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Caducidad (días)</label>
            <input
              type="number"
              min={1}
              value={expiresDays}
              onChange={(e) => setExpiresDays(e.target.value)}
              placeholder="opcional"
              className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-accent/60 focus:outline-none"
            />
          </div>
          <div className="sm:col-span-4 flex justify-end">
            <button
              type="submit"
              disabled={creating}
              className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-black hover:bg-accent-soft disabled:opacity-50 transition"
            >
              {creating ? <Loader2 size={14} className="animate-spin" /> : <UserPlus size={14} />}
              Crear token
            </button>
          </div>
        </form>

        {created && (
          <div className="mt-4 rounded-lg border border-accent/30 bg-accent/5 p-3">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">Token generado (cópialo, no se vuelve a mostrar)</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-data text-xs text-accent-soft break-all">{created}</code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(created).then(
                    () => { setCopied(true); setTimeout(() => setCopied(false), 1500); },
                    () => toast("No se pudo copiar.", "error"),
                  );
                }}
                className="shrink-0 text-slate-400 hover:text-accent transition"
              >
                {copied ? <Check size={15} /> : <Copy size={15} />}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Lista de tokens */}
      <div className="soc-panel p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="soc-label">Tokens emitidos</span>
          <button onClick={loadTokens} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-accent transition">
            <RefreshCw size={13} className={loadingList ? "animate-spin" : ""} /> Recargar
          </button>
        </div>

        {listError && <p className="text-xs text-red-400 mb-2">{listError}</p>}
        {tokens && tokens.length === 0 && <p className="text-xs text-slate-500">No hay tokens emitidos.</p>}

        {tokens && tokens.length > 0 && (
          <ul className="divide-y divide-white/5">
            {tokens.map((t) => (
              <li key={t.id} className="flex items-center gap-3 py-2 text-sm">
                <span className="text-gray-200 truncate max-w-[180px]">{t.label || "(sin nombre)"}</span>
                <span className={cn(
                  "rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider border",
                  t.role === "admin"
                    ? "bg-accent/15 text-accent-soft border-accent/30"
                    : "bg-slate-800 text-slate-400 border-slate-700",
                )}>
                  {t.role}
                </span>
                <span className="font-data text-xs text-slate-600">{t.key_preview}</span>
                {!t.active && <span className="text-[11px] text-red-400">revocado</span>}
                {t.expires_at && t.active && (
                  <span className="text-[11px] text-slate-600">caduca {t.expires_at.slice(0, 10)}</span>
                )}
                {t.active && (
                  <button
                    onClick={() => handleRevoke(t.id)}
                    className="ml-auto shrink-0 text-xs text-red-400/80 hover:text-red-400 transition"
                  >
                    Revocar
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
