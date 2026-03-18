// Cauldron API client

import type {
  StatsResponse,
  HostListResponse,
  HostOut,
  PathsResponse,
  GraphResponse,
  TopologyResponse,
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

export const api = {
  getStats: () => get<StatsResponse>('/stats'),

  getHosts: (params?: { role?: string; segment?: string; limit?: number; offset?: number }) =>
    get<HostListResponse>('/hosts', params as Record<string, string | number>),

  getHost: (ip: string) => get<HostOut>(`/hosts/${ip}`),

  getAttackPaths: (params?: { top?: number; include_check?: boolean; role?: string }) =>
    get<PathsResponse>('/attack-paths', params as Record<string, string | number | boolean>),

  getGraph: (limit?: number) => get<GraphResponse>('/graph', limit ? { limit } : undefined),

  getTopology: () => get<TopologyResponse>('/topology'),
};
