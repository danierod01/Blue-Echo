import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-react";

type ToastType = "success" | "error" | "info";

interface ToastItem {
  id: number;
  type: ToastType;
  message: string;
}

interface ToastContextValue {
  toast: (message: string, type?: ToastType) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

/** Hook para lanzar notificaciones toast desde cualquier componente. */
export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast debe usarse dentro de <ToastProvider>");
  return ctx;
}

const ICONS = {
  success: CheckCircle2,
  error: AlertCircle,
  info: Info,
} as const;

const ACCENT: Record<ToastType, string> = {
  success: "text-emerald-400 border-emerald-500/30",
  error: "text-red-400 border-red-500/30",
  info: "text-blue-400 border-blue-500/30",
};

let _seq = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(
    (message: string, type: ToastType = "info") => {
      const id = ++_seq;
      setToasts((list) => [...list, { id, type, message }]);
      // Auto-cierre a los 4s.
      setTimeout(() => remove(id), 4000);
    },
    [remove]
  );

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
        {toasts.map((t) => {
          const Icon = ICONS[t.type];
          return (
            <div
              key={t.id}
              role="status"
              className={`flex items-start gap-2 rounded-lg border bg-gray-900/95 backdrop-blur px-3 py-2 shadow-lg animate-[fadeSlideIn_0.25s_ease] ${ACCENT[t.type]}`}
            >
              <Icon size={15} className="shrink-0 mt-0.5" />
              <span className="text-sm text-gray-200 flex-1">{t.message}</span>
              <button
                onClick={() => remove(t.id)}
                className="shrink-0 text-gray-500 hover:text-gray-300"
                aria-label="Cerrar"
              >
                <X size={13} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
