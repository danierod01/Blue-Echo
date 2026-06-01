import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const VERDICT_LABEL: Record<string, string> = {
  clean:      "LIMPIO",
  suspicious: "SOSPECHOSO",
  malicious:  "MALICIOSO",
  critical:   "CRÍTICO",
  pcap:       "CAPTURA DE RED",
};

export const VERDICT_COLOR: Record<string, string> = {
  critical:   "text-red-400",
  malicious:  "text-orange-400",
  suspicious: "text-yellow-400",
  clean:      "text-green-400",
  pcap:       "text-purple-400",
};

export const VERDICT_BORDER: Record<string, string> = {
  critical:   "border-red-500",
  malicious:  "border-orange-500",
  suspicious: "border-yellow-500",
  clean:      "border-green-500",
  pcap:       "border-purple-500",
};

export const VERDICT_BG: Record<string, string> = {
  critical:   "bg-red-500/10",
  malicious:  "bg-orange-500/10",
  suspicious: "bg-yellow-500/10",
  clean:      "bg-green-500/10",
  pcap:       "bg-purple-500/10",
};

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("es-ES", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}
