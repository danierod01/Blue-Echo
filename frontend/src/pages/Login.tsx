import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, KeyRound, Loader2 } from "lucide-react";
import { verifyApiKey, setStoredApiKey } from "@/api/client";

export default function Login() {
  const navigate = useNavigate();
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!apiKey.trim()) {
      setError("Introduce una API key.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const valid = await verifyApiKey(apiKey.trim());
      if (valid) {
        setStoredApiKey(apiKey.trim());
        navigate("/", { replace: true });
      } else {
        setError("API key incorrecta. Inténtalo de nuevo.");
      }
    } catch {
      setError("No se pudo conectar con el servidor.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center gap-3 mb-8">
          <div className="p-3 rounded-full bg-blue-500/10 border border-blue-500/20">
            <ShieldAlert size={32} className="text-blue-400" />
          </div>
          <h1 className="text-2xl font-bold text-white">Blue-Echo</h1>
          <p className="text-sm text-gray-400">Introduce tu API key para acceder</p>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="relative">
            <KeyRound
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
            />
            <input
              type="password"
              placeholder="API key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-gray-900 border border-gray-700 text-white placeholder-gray-500 text-sm focus:outline-none focus:border-blue-500 transition"
              autoFocus
            />
          </div>

          {error && (
            <p className="text-xs text-red-400 text-center">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex items-center justify-center gap-2 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition"
          >
            {loading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              "Iniciar sesión"
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
