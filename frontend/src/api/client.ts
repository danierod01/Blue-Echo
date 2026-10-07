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
  reason?: string;
  description?: string;
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
  pivots?: PivotEntity[];
  triage?: TriageState;
  note?: string;
  tags?: string[];
}

export type TriageState = "new" | "investigating" | "confirmed" | "false_positive" | "resolved";

export interface PivotEntity {
  value: string;
  ioc_type: string;
  relation: string;
  source: string;
}

export interface HistoryItem {
  id: number;
  ioc_value: string;
  ioc_type: string;
  score: number;
  verdict: "clean" | "suspicious" | "malicious" | "critical";
  created_at: string;
  triage?: TriageState;
  tags?: string[];
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

export async function getPcapScanById(id: number): Promise<PcapScanResponse> {
  const res = await fetch(`${BASE_URL}/api/history/${id}/pcap`, {
    headers: authHeaders(),
  });
  return handleResponse<PcapScanResponse>(res);
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

/**
 * Descarga el informe PDF de un escaneo. Se hace vía fetch (no <a href>)
 * porque el endpoint requiere la cabecera X-API-Key; el blob resultante se
 * descarga disparando un enlace temporal.
 */
export async function downloadScanPdf(id: number, iocValue?: string): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/history/${id}/pdf`, {
    headers: authHeaders(),
  });
  if (res.status === 401) {
    clearStoredApiKey();
    window.location.href = "/login";
    throw new Error("Sesión expirada.");
  }
  if (!res.ok) {
    throw new Error(`No se pudo generar el PDF (HTTP ${res.status}).`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safe = (iocValue ?? String(id)).replace(/[^a-zA-Z0-9._-]/g, "_");
  a.download = `blue-echo-${safe}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Descarga el escaneo en formato SIEM/TI (STIX 2.1 o MISP) — roadmap I2. */
export async function downloadScanExport(
  id: number,
  format: "stix" | "misp",
  iocValue?: string,
): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/history/${id}/export?format=${format}`, {
    headers: authHeaders(),
  });
  if (res.status === 401) {
    clearStoredApiKey();
    window.location.href = "/login";
    throw new Error("Sesión expirada.");
  }
  if (!res.ok) {
    throw new Error(`No se pudo exportar (HTTP ${res.status}).`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safe = (iocValue ?? String(id)).replace(/[^a-zA-Z0-9._-]/g, "_");
  a.download = `blue-echo-${safe}-${format}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export interface RuleBundle {
  ioc: string;
  ioc_type: string;
  formats: Record<string, string>;
}

async function fetchRuleBundle(id: number, path: string): Promise<RuleBundle> {
  const res = await fetch(`${BASE_URL}/api/history/${id}/${path}`, {
    headers: authHeaders(),
  });
  if (res.status === 401) {
    clearStoredApiKey();
    window.location.href = "/login";
    throw new Error("Sesión expirada.");
  }
  if (!res.ok) {
    throw new Error(`No se pudieron generar las reglas (HTTP ${res.status}).`);
  }
  return res.json();
}

/** Reglas de bloqueo/respuesta (iptables, pf, cisco, hosts…). */
export function getBlockRules(id: number): Promise<RuleBundle> {
  return fetchRuleBundle(id, "blocklist");
}

/** Reglas de detección (Sigma, Suricata, YARA). */
export function getDetectionRules(id: number): Promise<RuleBundle> {
  return fetchRuleBundle(id, "detection-rules");
}

export async function getSources(): Promise<SourceStatus[]> {
  const res = await fetch(`${BASE_URL}/api/sources`, {
    headers: authHeaders(),
  });
  return handleResponse<SourceStatus[]>(res);
}

export interface MeResponse {
  name: string;
  role: string;
}

export async function getMe(): Promise<MeResponse> {
  const res = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: authHeaders(),
  });
  return handleResponse<MeResponse>(res);
}

export interface TokenInfo {
  id: number;
  label: string;
  role: string;
  key_preview: string;
  active: boolean;
  created_at: string;
  expires_at: string | null;
}

/** Lista los tokens emitidos (requiere el ADMIN_SECRET). */
export async function listTokens(adminSecret: string): Promise<TokenInfo[]> {
  const res = await fetch(`${BASE_URL}/api/auth/tokens`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ admin_secret: adminSecret }),
  });
  if (!res.ok) throw new Error("No autorizado o error listando tokens.");
  return res.json() as Promise<TokenInfo[]>;
}

/** Revoca (desactiva) un token por id (requiere el ADMIN_SECRET). */
export async function revokeToken(adminSecret: string, tokenId: number): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/auth/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ admin_secret: adminSecret, token_id: tokenId }),
  });
  if (!res.ok) throw new Error("No se pudo revocar el token.");
}

// ---------------------------------------------------------------------------
// Panel de administración — autorizado por la SESIÓN admin (cabecera X-API-Key),
// no por el ADMIN_SECRET. El backend solo lo permite si el token de la sesión
// tiene rol admin (o es la master key).
// ---------------------------------------------------------------------------

export async function adminListTokens(): Promise<TokenInfo[]> {
  const res = await fetch(`${BASE_URL}/api/auth/tokens`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ admin_secret: "" }),
  });
  if (!res.ok) throw new Error("No autorizado o error listando tokens.");
  return res.json() as Promise<TokenInfo[]>;
}

export async function adminRevokeToken(tokenId: number): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/auth/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ admin_secret: "", token_id: tokenId }),
  });
  if (!res.ok) throw new Error("No se pudo revocar el token.");
}

// --- Códigos de invitación ---

export interface InviteCodeInfo {
  id: number;
  code: string;
  role: string;
  label: string;
  active: boolean;
  used: boolean;
  used_by: string;
  expires_at: string | null;
  created_at: string;
}

/** Genera un código de invitación para repartir (admin). */
export async function adminCreateInviteCode(
  p: { label: string; role: string; expiresInDays?: number | null },
): Promise<InviteCodeInfo> {
  const res = await fetch(`${BASE_URL}/api/auth/invite-codes/create`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({
      admin_secret: "",
      label: p.label,
      role: p.role,
      expires_in_days: p.expiresInDays ?? null,
    }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    throw new Error(d.detail ?? "No se pudo crear el código.");
  }
  return res.json() as Promise<InviteCodeInfo>;
}

export async function adminListInviteCodes(): Promise<InviteCodeInfo[]> {
  const res = await fetch(`${BASE_URL}/api/auth/invite-codes/list`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ admin_secret: "" }),
  });
  if (!res.ok) throw new Error("No autorizado o error listando códigos.");
  return res.json() as Promise<InviteCodeInfo[]>;
}

export async function adminRevokeInviteCode(codeId: number): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/auth/invite-codes/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ admin_secret: "", code_id: codeId }),
  });
  if (!res.ok) throw new Error("No se pudo revocar el código.");
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

// ---------------------------------------------------------------------------
// Watchlist / monitorización continua (SOC-B)
// ---------------------------------------------------------------------------

export interface WatchedIoc {
  id: number;
  ioc_value: string;
  ioc_type: string;
  note: string;
  last_score: number | null;
  last_verdict: string | null;
  last_checked_at: string | null;
  created_at: string;
}

export interface WatchAlert {
  id: number;
  ioc_value: string;
  ioc_type: string;
  old_verdict: string | null;
  new_verdict: string;
  old_score: number | null;
  new_score: number;
  acknowledged: boolean;
  created_at: string;
}

export async function addWatched(ioc: string): Promise<WatchedIoc> {
  const res = await fetch(`${BASE_URL}/api/watchlist`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ ioc }),
  });
  return handleResponse<WatchedIoc>(res);
}

export async function listWatched(): Promise<WatchedIoc[]> {
  const res = await fetch(`${BASE_URL}/api/watchlist`, { headers: authHeaders() });
  return handleResponse<WatchedIoc[]>(res);
}

export async function removeWatched(id: number): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/watchlist/${id}`, {
    method: "DELETE",
    headers: authHeaders(),
  });
  await handleResponse<unknown>(res);
}

export async function checkWatched(id: number): Promise<WatchedIoc & { alert: WatchAlert | null }> {
  const res = await fetch(`${BASE_URL}/api/watchlist/${id}/check`, {
    method: "POST",
    headers: authHeaders(),
  });
  return handleResponse<WatchedIoc & { alert: WatchAlert | null }>(res);
}

export async function listWatchAlerts(): Promise<WatchAlert[]> {
  const res = await fetch(`${BASE_URL}/api/watchlist/alerts`, { headers: authHeaders() });
  return handleResponse<WatchAlert[]>(res);
}

export async function ackWatchAlert(id: number): Promise<void> {
  const res = await fetch(`${BASE_URL}/api/watchlist/alerts/${id}/ack`, {
    method: "POST",
    headers: authHeaders(),
  });
  await handleResponse<unknown>(res);
}

// ---------------------------------------------------------------------------
// Estadísticas / dashboard SOC (SOC-D)
// ---------------------------------------------------------------------------

export interface SocStats {
  total_scans: number;
  verdict_counts: Record<string, number>;
  type_counts: Record<string, number>;
  timeline: { date: string; count: number }[];
  top_threats: { ioc_value: string; ioc_type: string; score: number; verdict: string }[];
  watchlist: { watched: number; open_alerts: number };
}

export async function getStats(): Promise<SocStats> {
  const res = await fetch(`${BASE_URL}/api/stats`, { headers: authHeaders() });
  return handleResponse<SocStats>(res);
}

// ---------------------------------------------------------------------------
// Triaje del analista (A-lite)
// ---------------------------------------------------------------------------

export async function updateTriage(
  id: number,
  body: { triage?: TriageState; note?: string; tags?: string[] },
): Promise<ScanResponse> {
  const res = await fetch(`${BASE_URL}/api/history/${id}/triage`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
  });
  return handleResponse<ScanResponse>(res);
}
