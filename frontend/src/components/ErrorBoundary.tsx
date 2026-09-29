import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  message: string;
}

/**
 * Error boundary global. Captura errores de render de React para que un fallo
 * en un componente no deje la aplicación en blanco, sino que muestre una
 * pantalla de recuperación con opción de recargar.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, message: "" };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, message: error.message };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Log para depuración (visible en la consola del navegador).
    console.error("ErrorBoundary capturó un error:", error, info);
  }

  render(): ReactNode {
    if (!this.state.hasError) return this.props.children;

    return (
      <div className="min-h-screen bg-[#08080f] flex flex-col items-center justify-center text-center px-4">
        <AlertTriangle size={40} className="text-red-400 mb-4" />
        <h1 className="text-lg font-semibold text-gray-100">Algo ha ido mal</h1>
        <p className="mt-1 text-sm text-gray-500 max-w-md">
          Se ha producido un error inesperado en la interfaz. Puedes recargar la página
          para continuar.
        </p>
        {this.state.message && (
          <code className="mt-3 font-data text-xs text-red-400/80 max-w-md break-all">
            {this.state.message}
          </code>
        )}
        <button
          onClick={() => window.location.reload()}
          className="mt-6 rounded-lg bg-blue-600 hover:bg-blue-500 px-4 py-2 text-sm font-medium text-white transition"
        >
          Recargar
        </button>
      </div>
    );
  }
}
