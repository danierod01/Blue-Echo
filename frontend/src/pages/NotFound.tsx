import { Link } from "react-router-dom";
import { Radar, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center px-4">
      <div className="flex items-center gap-2 mb-6 opacity-70">
        <Radar size={20} className="text-blue-400" />
        <span className="font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
          BlueEcho
        </span>
      </div>
      <p className="font-data text-6xl font-black text-blue-500/80">404</p>
      <h1 className="mt-3 text-lg font-semibold text-gray-200">Página no encontrada</h1>
      <p className="mt-1 text-sm text-gray-500 max-w-sm">
        La ruta que buscas no existe o se ha movido.
      </p>
      <Link
        to="/"
        className="mt-6 inline-flex items-center gap-2 rounded-lg border border-gray-700/60 bg-gray-900/60 px-4 py-2 text-sm text-gray-300 transition hover:border-blue-500/60 hover:text-blue-300"
      >
        <ArrowLeft size={14} /> Volver al panel
      </Link>
    </div>
  );
}
