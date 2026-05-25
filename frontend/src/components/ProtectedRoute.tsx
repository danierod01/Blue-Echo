import { Navigate } from "react-router-dom";
import { getStoredApiKey } from "@/api/client";

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const key = getStoredApiKey();

  // Si no hay key en localStorage, redirige al login
  // En modo dev (sin BLUE_ECHO_API_KEY en el backend), cualquier key pasa.
  // Si la app no tiene auth configurada, se puede entrar con cualquier valor.
  if (!key) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
