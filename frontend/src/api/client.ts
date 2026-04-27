const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

export interface ConnectorResult {
  source: string;
  success: boolean;
  verdict: string;
  summary: string;
  data: Record<string, unknown>;
  error?: string;
}

export interface ScanResponse {
  id: number;
  ioc_value: string;
  ioc_type: string;
  score: number;
  verdict: "clean" | "suspicious" | "malicious" | "critical";
  breakdown: Record<string, number>;
  connector_results: Record<string, ConnectorResult>;
  ai_summary: string;
  created_at: string;
}

export interface HistoryItem {
  id: number;
  ioc_value: string;
  ioc_type: string;
  score: number;
  verdict: "clean" | "suspicious" | "malicious" | "critical";
  created_at: string;
}

export interface SourceStatus {
  name: string;
  available: boolean;
  supported_types: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
    throw new Error(body.detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Llamadas a la API
// ---------------------------------------------------------------------------

export async function scanIoc(ioc: string): Promise<ScanResponse> {
  const res = await fetch(`${BASE_URL}/api/scan/json`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });
  return handleResponse<ScanResponse>(res);
}

export async function scanFile(file: File): Promise<ScanResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE_URL}/api/scan`, { method: "POST", body: form });
  return handleResponse<ScanResponse>(res);
}

export async function getHistory(limit = 50): Promise<HistoryItem[]> {
  const res = await fetch(`${BASE_URL}/api/history?limit=${limit}`);
  return handleResponse<HistoryItem[]>(res);
}

export async function getScanById(id: number): Promise<ScanResponse> {
  const res = await fetch(`${BASE_URL}/api/history/${id}`);
  return handleResponse<ScanResponse>(res);
}

export async function getSources(): Promise<SourceStatus[]> {
  const res = await fetch(`${BASE_URL}/api/sources`);
  return handleResponse<SourceStatus[]>(res);
}
