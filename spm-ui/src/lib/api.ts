const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

async function headers(): Promise<Record<string, string>> {
  try {
    const { getToken } = await import("./auth");
    return { "Content-Type": "application/json", Authorization: `Bearer ${await getToken()}` };
  } catch {
    return { "Content-Type": "application/json" };
  }
}

async function get<T = any>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: await headers(), cache: "no-store" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function post<T = any>(path: string, body?: any): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { method: "POST", headers: await headers(), body: body ? JSON.stringify(body) : undefined });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function put<T = any>(path: string, body: any): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { method: "PUT", headers: await headers(), body: JSON.stringify(body) });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// --- Observe ---
export const getDashboard = () => get("/spm/api/dashboard");
export const getInventory = (source?: string) => get(`/spm/api/inventory${source ? `?source=${source}` : ""}`);
export const getAgent = (id: string) => get(`/spm/api/inventory/${id}`);
export const getTopology = () => get("/spm/api/topology");
export const triggerScan = () => post("/spm/api/scan");

// --- Govern ---
export const getFindings = (params?: { severity?: string; status?: string; agent_id?: string }) => {
  const q = new URLSearchParams(params as any).toString();
  return get(`/spm/api/findings${q ? `?${q}` : ""}`);
};
export const acknowledgeFinding = (id: string) => post(`/spm/api/findings/${id}/acknowledge`);
export const resolveFinding = (id: string) => post(`/spm/api/findings/${id}/resolve`);
export const triggerEvaluation = () => post("/spm/api/evaluate");
export const getPolicies = () => get("/spm/api/policies");
export const updatePolicy = (id: string, enabled: boolean) => put(`/spm/api/policies/${id}`, { enabled });
export const createPolicy = (body: { name: string; description?: string; rules?: any[]; compliance_framework?: string; enabled?: boolean }) => post("/spm/api/policies", body);
export const deletePolicy = (id: string) => del(`/spm/api/policies/${id}`);

async function del<T = any>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { method: "DELETE", headers: await headers() });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// --- Defend ---
export const getRuntimeEvents = (limit = 25, cursor?: string) => {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set("cursor", cursor);
  return get(`/spm/api/runtime/events?${params}`);
};
export const getRuntimeAlerts = () => get("/spm/api/runtime/alerts");
export const getRuntimeStats = () => get("/spm/api/runtime/stats");
export const getDefenderConfig = () => get("/spm/api/defender/config");
export const setDefenderMode = (mode: string) => put("/spm/api/defender/mode", { mode });
export const setDefenderRules = (rules: any) => put("/spm/api/defender/rules", { rules });
export const remediate = (action: string, target: string, reason: string) => post("/spm/api/remediate", { action, target, reason });
export const runCorrelation = () => post("/spm/api/correlate");
