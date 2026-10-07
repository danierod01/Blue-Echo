import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, Ticket, RefreshCw, Copy, Check, Loader2, Lock, KeyRound } from "lucide-react";
import {
  getMe,
  adminListTokens, adminRevokeToken, type TokenInfo,
  adminCreateInviteCode, adminListInviteCodes, adminRevokeInviteCode, type InviteCodeInfo,
} from "@/api/client";
import { useToast } from "@/components/Toast";
import { cn } from "@/lib/utils";

/**
 * Panel de administración — SOLO para sesiones con rol admin.
 * El admin GENERA códigos de invitación (que reparte para que la gente se
 * registre en /invite) y REVOCA tokens o códigos. Autorizado por el backend
 * contra la X-API-Key de la sesión admin.
 */
export default function AdminPanel() {
  const { toast } = useToast();
  const me = useQuery({ queryKey: ["me"], queryFn: getMe });
  const isAdmin = me.data?.role === "admin";

  // Formulario de creación de código
  const [label, setLabel] = useState("");
  const [role, setRole] = useState("analyst");
  const [expiresDays, setExpiresDays] = useState("");
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [codes, setCodes] = useState<InviteCodeInfo[] | null>(null);
  const [tokens, setTokens] = useState<TokenInfo[] | null>(null);
  const [loadingLists, setLoadingLists] = useState(false);
  const [listError, setListError] = useState<string | null>(null);

  async function loadAll() {
    setLoadingLists(true);
    setListError(null);
    try {
      const [c, t] = await Promise.all([adminListInviteCodes(), adminListTokens()]);
      setCodes(c);
      setTokens(t);
    } catch (e) {
      setListError(e instanceof Error ? e.message : "Error cargando datos.");
    } finally {
      setLoadingLists(false);
    }
  }

  useEffect(() => {
    if (isAdmin) loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setCreated(null);
    try {
      const res = await adminCreateInviteCode({
        label: label.trim(),
        role,
        expiresInDays: expiresDays ? Number(expiresDays) : null,
      });
      setCreated(res.code);
      setLabel("");
      setExpiresDays("");
      toast("Código de invitación generado.", "success");
      await loadAll();
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo generar el código.", "error");
    } finally {
      setCreating(false);
    }
  }

  async function revokeCode(id: number) {
    try {
      await adminRevokeInviteCode(id);
      toast("Código revocado.", "success");
      await loadAll();
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo revocar el código.", "error");
    }
  }

  async function revokeTok(id: number) {
    try {
      await adminRevokeToken(id);
      toast("Token revocado.", "success");
      await loadAll();
    } catch (e) {
      toast(e instanceof Error ? e.message : "No se pudo revocar el token.", "error");
    }
  }

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

  const roleBadge = (r: string) => cn(
    "rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider border",
    r === "admin" ? "bg-accent/15 text-accent-soft border-accent/30" : "bg-slate-800 text-slate-400 border-slate-700",
  );

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck size={22} className="text-accent" />
          Administración
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Genera códigos de invitación para repartir, y revoca tokens o códigos.
        </p>
      </div>

      {/* Generar código de invitación */}
      <div className="soc-panel p-5">
        <div className="flex items-center gap-2 mb-3">
          <Ticket size={15} className="text-accent" />
          <span className="soc-label">Generar código de invitación</span>
        </div>
        <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div className="sm:col-span-2">
            <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Nota (para quién / para qué)</label>
            <input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="p. ej. Invitación para Jose"
              className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-accent/60 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[11px] text-gray-500 mb-1 uppercase tracking-wider">Rol que concede</label>
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
              {creating ? <Loader2 size={14} className="animate-spin" /> : <Ticket size={14} />}
              Generar código
            </button>
          </div>
        </form>

        {created && (
          <div className="mt-4 rounded-lg border border-accent/30 bg-accent/5 p-3">
            <p className="text-[11px] text-gray-500 uppercase tracking-wider mb-1">
              Código generado — repártelo a la persona (se canjea en /invite)
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-data text-sm text-accent-soft break-all">{created}</code>
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

      {/* Códigos de invitación */}
      <div className="soc-panel p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="soc-label flex items-center gap-1.5"><Ticket size={13} /> Códigos de invitación</span>
          <button onClick={loadAll} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-accent transition">
            <RefreshCw size={13} className={loadingLists ? "animate-spin" : ""} /> Recargar
          </button>
        </div>
        {listError && <p className="text-xs text-red-400 mb-2">{listError}</p>}
        {codes && codes.length === 0 && <p className="text-xs text-slate-500">No hay códigos. Genera uno arriba.</p>}
        {codes && codes.length > 0 && (
          <ul className="divide-y divide-white/5">
            {codes.map((c) => (
              <li key={c.id} className="flex items-center gap-3 py-2 text-sm">
                <code className="font-data text-xs text-slate-300 break-all">{c.code}</code>
                <span className={roleBadge(c.role)}>{c.role}</span>
                {c.used ? (
                  <span className="text-[11px] text-slate-500">usado por {c.used_by || "?"}</span>
                ) : !c.active ? (
                  <span className="text-[11px] text-red-400">revocado</span>
                ) : (
                  <span className="text-[11px] text-emerald-400">disponible</span>
                )}
                {c.label && <span className="text-[11px] text-slate-600 truncate max-w-[160px]">· {c.label}</span>}
                {c.active && !c.used && (
                  <button onClick={() => revokeCode(c.id)} className="ml-auto shrink-0 text-xs text-red-400/80 hover:text-red-400 transition">
                    Revocar
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Tokens emitidos */}
      <div className="soc-panel p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="soc-label flex items-center gap-1.5"><KeyRound size={13} /> Tokens emitidos</span>
        </div>
        {tokens && tokens.length === 0 && <p className="text-xs text-slate-500">No hay tokens emitidos.</p>}
        {tokens && tokens.length > 0 && (
          <ul className="divide-y divide-white/5">
            {tokens.map((t) => (
              <li key={t.id} className="flex items-center gap-3 py-2 text-sm">
                <span className="text-gray-200 truncate max-w-[180px]">{t.label || "(sin nombre)"}</span>
                <span className={roleBadge(t.role)}>{t.role}</span>
                <span className="font-data text-xs text-slate-600">{t.key_preview}</span>
                {!t.active && <span className="text-[11px] text-red-400">revocado</span>}
                {t.expires_at && t.active && (
                  <span className="text-[11px] text-slate-600">caduca {t.expires_at.slice(0, 10)}</span>
                )}
                {t.active && (
                  <button onClick={() => revokeTok(t.id)} className="ml-auto shrink-0 text-xs text-red-400/80 hover:text-red-400 transition">
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
