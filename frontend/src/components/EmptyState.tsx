export default function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-20 select-none">
      {/* Radar animado */}
      <div className="relative w-40 h-40 mb-8">
        {/* Anillos concéntricos */}
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="absolute inset-0 rounded-full border border-accent/10"
            style={{ transform: `scale(${i * 0.25})`, transformOrigin: "center" }}
          />
        ))}
        {/* Ping exterior */}
        <div className="absolute inset-0 rounded-full border border-accent/20 animate-radarPing" />
        <div
          className="absolute inset-0 rounded-full border border-accent/10 animate-radarPing"
          style={{ animationDelay: "1s" }}
        />
        {/* Sweep line */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div
            className="absolute w-1/2 h-px origin-left animate-radarSweep"
            style={{
              background: "linear-gradient(to right, rgba(45,212,191,0.85), transparent)",
              left: "50%",
              top: "50%",
            }}
          />
        </div>
        {/* Punto central */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-2 h-2 rounded-full bg-accent shadow-[0_0_10px_var(--soc-accent)]" />
        </div>
        {/* Fondo radial */}
        <div className="absolute inset-0 rounded-full bg-gradient-to-br from-accent/5 to-transparent" />
      </div>

      <p className="soc-label text-accent/70">Sistema listo</p>
      <p className="text-sm font-medium text-slate-400 tracking-wide mt-2">
        Esperando indicador de compromiso
      </p>
      <p className="text-xs text-slate-600 mt-1">
        Introduce un IOC arriba o sube un fichero
      </p>
    </div>
  );
}
