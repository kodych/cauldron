// Cauldron API client

import type {
  StatsResponse,
  HostListResponse,
  HostOut,
  PathsResponse,
  GraphResponse,
  TopologyResponse,
  CollectResponse,
  ImportResponse,
  AnalyzeResponse,
  VulnStatus,
} from '../types';

const BASE = '/api/v1';

async function get<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T> {
  const url = new URL(`${BASE}${path}`, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        url.searchParams.set(k, String(v));
      }
    }
  }
  const res = await fetch(url.toString());
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`API ${res.status}: ${detail}`);
  }
  return res.json();
}

async function post<T>(path: string, params?: Record<string, string | number | boolean>, timeoutMs = 600000): Promise<T> {
  const url = new URL(`${BASE}${path}`, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        url.searchParams.set(k, String(v));
      }
    }
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url.toString(), { method: 'POST', signal: controller.signal });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`API ${res.status}: ${detail}`);
    }
    return res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const url = new URL(`${BASE}${path}`, window.location.origin);
  const res = await fetch(url.toString(), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`API ${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  getStats: () => get<StatsResponse>('/stats'),

  getHosts: (params?: { role?: string; segment?: string; limit?: number; offset?: number }) =>
    get<HostListResponse>('/hosts', params as Record<string, string | number>),

  getHost: (ip: string) => get<HostOut>(`/hosts/${ip}`),

  getAttackPaths: (params?: { top?: number; include_check?: boolean; role?: string }) =>
    get<PathsResponse>('/attack-paths', params as Record<string, string | number | boolean>),

  getGraph: (limit?: number) => get<GraphResponse>('/graph', limit ? { limit } : undefined),

  getTopology: () => get<TopologyResponse>('/topology'),

  getCollect: (params: { filter?: string; port?: number; role?: string; source?: string }) =>
    get<CollectResponse>('/collect', params as Record<string, string | number>),

  getCollectFilters: () => get<Record<string, string>>('/collect/filters'),

  importScan: async (file: File, source?: string): Promise<ImportResponse> => {
    const url = new URL(`${BASE}/import`, window.location.origin);
    if (source) url.searchParams.set('source', source);
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(url.toString(), { method: 'POST', body: form });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`API ${res.status}: ${detail}`);
    }
    return res.json();
  },

  runAnalysis: (options?: { nvd?: boolean; ai?: boolean }) =>
    post<AnalyzeResponse>('/analyze', options),

  setHostOwned: (ip: string, owned: boolean) =>
    patch<{ ok: boolean }>(`/hosts/${ip}/owned`, { value: owned }),

  setHostTarget: (ip: string, target: boolean) =>
    patch<{ ok: boolean }>(`/hosts/${ip}/target`, { value: target }),

  getDefaultCreds: (ip: string, port: number) =>
    get<{ ip: string; port: number; creds: Array<{ username: string; password: string }> }>(
      `/hosts/${ip}/services/${port}/default-creds`,
    ),

  updateVulnStatus: (ip: string, vulnId: string, status: VulnStatus, port?: number | null) =>
    patch<{ ok: boolean }>(`/hosts/${ip}/vulns/${encodeURIComponent(vulnId)}/status`, { status, port }),

  updateServiceBruteforceable: (ip: string, port: number, bruteforceable: boolean) =>
    patch<{ ok: boolean }>(`/hosts/${ip}/services/${port}/bruteforceable`, { bruteforceable }),

  updateServiceNotes: (ip: string, port: number, notes: string | null) =>
    patch<{ ok: boolean }>(`/hosts/${ip}/services/${port}/notes`, { notes }),

  updateHostNotes: (ip: string, notes: string | null) =>
    patch<{ ok: boolean }>(`/hosts/${ip}/notes`, { notes }),

  resetDatabase: async (): Promise<{ ok: boolean }> => {
    const url = new URL(`${BASE}/reset`, window.location.origin);
    const res = await fetch(url.toString(), { method: 'DELETE' });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`API ${res.status}: ${detail}`);
    }
    return res.json();
  },
};
