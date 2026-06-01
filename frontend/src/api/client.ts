const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

const SESSION_KEY = "blueecho_api_key";

export function getStoredApiKey(): string {
  return localStorage.getItem(SESSION_KEY) ?? "";
}

export function setStoredApiKey(key: string): void {
  localStorage.setItem(SESSION_KEY, key);
}

export function clearStoredApiKey(): void {
  localStorage.removeItem(SESSION_KEY);
}

function authHeaders(): HeadersInit {
  const key = getStoredApiKey();
  return key ? { "X-API-Key": key } : {};
}

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  source: string;
}

export interface ConnectorResult {
  source: string;
  success: boolean;
  verdict: string;
  summary: string;
  data: Record<string, unknown>;
  error?: string;
}

export interface GeoLocation {
  lat: number;
  lon: number;
  city: string;
  region: string;
  country: string;
  country_code: string;
  org?: string;
  resolved_ip?: string;
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
  mitre_techniques: MitreTechnique[];
  geolocation?: GeoLocation | null;
}

export interface HistoryItem {
  id: number;
  ioc_value: string;
  ioc_type: string;
  score: number;
  verdict: "clean" | "suspicious" | "malicious" | "critical";
  created_at: string;
}

export interface HistoryPage {
  items: HistoryItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface HistoryParams {
  limit?: number;
  offset?: number;
  ioc_type?: string;   // valores separados por coma
  verdict?: string;
  search?: string;
}

export interface SourceStatus {
  name: string;
  available: boolean;
  supported_types: string[];
}

export interface PcapIocItem {
  value: string;
  ioc_type: string;
}

export interface PcapTrafficStats {
  total_packets: number;
  total_bytes: number;
  unique_src_ips: string[];
  unique_dst_ips: string[];
  top_connections: Array<{ src: string; dst: string; packets: number }>;
  dns_queries: string[];
  http_hosts: string[];
  tls_sni: string[];
  protocols: Record<string, number>;
}

export interface ExtractedObject {
  filename: string;
  content_type: string;
  size: number;
  extension: string;
  suspicious: boolean;
  src_ip: string;
  dst_ip: string;
  data_b64: string;
}

export interface PcapScanResponse {
  filename: string;
  ai_summary: string;
  iocs_found: PcapIocItem[];
  total_iocs: number;
  stats: PcapTrafficStats;
  extracted_objects: ExtractedObject[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    clearStoredApiKey();
    window.location.href = "/login";
    throw new Error("Sesión expirada.");
  }
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
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ ioc }),
  });
  return handleResponse<ScanResponse>(res);
}

export async function scanFile(file: File): Promise<ScanResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE_URL}/api/scan`, {
    method: "POST",
    headers: authHeaders(),
    body: form,
  });
  return handleResponse<ScanResponse>(res);
}

export async function getHistory(params: HistoryParams = {}): Promise<HistoryPage> {
  const q = new URLSearchParams();
  if (params.limit   !== undefined) q.set("limit",    String(params.limit));
  if (params.offset  !== undefined) q.set("offset",   String(params.offset));
  if (params.ioc_type)              q.set("ioc_type", params.ioc_type);
  if (params.verdict)               q.set("verdict",  params.verdict);
  if (params.search)                q.set("search",   params.search);
  const res = await fetch(`${BASE_URL}/api/history?${q}`, {
    headers: authHeaders(),
  });
  return handleResponse<HistoryPage>(res);
}

export async function getScanById(id: number): Promise<ScanResponse> {
  const res = await fetch(`${BASE_URL}/api/history/${id}`, {
    headers: authHeaders(),
  });
  return handleResponse<ScanResponse>(res);
}

export async function scanPcap(file: File): Promise<PcapScanResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE_URL}/api/scan/pcap`, {
    method: "POST",
    headers: authHeaders(),
    body: form,
  });
  return handleResponse<PcapScanResponse>(res);
}

export async function getSources(): Promise<SourceStatus[]> {
  const res = await fetch(`${BASE_URL}/api/sources`, {
    headers: authHeaders(),
  });
  return handleResponse<SourceStatus[]>(res);
}

export async function verifyApiKey(apiKey: string): Promise<boolean> {
  const res = await fetch(`${BASE_URL}/api/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: apiKey }),
  });
  if (!res.ok) return false;
  const data = await res.json();
  return data.valid === true;
}
