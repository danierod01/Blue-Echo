import { Link } from "react-router-dom";
import { Radar, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center px-4">
      <div className="flex items-center gap-2 mb-6 opacity-70">
        <Radar size={20} className="text-accent" />
        <span className="font-bold bg-gradient-to-r from-accent-soft to-accent-cyan bg-clip-text text-transparent">
          BlueEcho
        </span>
      </div>
      <p className="font-data text-6xl font-black text-accent/80">404</p>
      <h1 className="mt-3 text-lg font-semibold text-gray-200">Página no encontrada</h1>
      <p className="mt-1 text-sm text-gray-500 max-w-sm">
        La ruta que buscas no existe o se ha movido.
      </p>
      <Link
        to="/"
        className="mt-6 inline-flex items-center gap-2 rounded-lg border border-gray-700/60 bg-gray-900/60 px-4 py-2 text-sm text-gray-300 transition hover:border-accent/60 hover:text-accent-soft"
      >
        <ArrowLeft size={14} /> Volver al panel
      </Link>
    </div>
  );
}
