// Types matching Cauldron API response models

export interface StatsResponse {
  hosts: number;
  services: number;
  segments: number;
  vulnerabilities: number;
  findings: number;
  scan_sources: number;
  roles: Record<string, number>;
}

export interface ServiceOut {
  port: number;
  protocol: string;
  state: string | null;
  name: string | null;
  product: string | null;
  version: string | null;
  bruteforceable: boolean;
  notes: string | null;
  is_new: boolean;
  is_stale: boolean;
}

export interface VulnOut {
  cve_id: string;
  cvss: number;
  has_exploit: boolean;
  exploit_url: string | null;
  exploit_module: string | null;
  confidence: string;
  description: string | null;
  enables_pivot: boolean | null;
  checked_status: string | null;
  ai_fp_reason: string | null;
  port: number | null;
  source: string | null; // exploit_db, nvd, ai
  in_cisa_kev: boolean;
  cisa_kev_added: string | null;
}

export interface HostOut {
  ip: string;
  hostname: string | null;
  role: string;
  role_confidence: number;
  os_name: string | null;
  segment: string | null;
  is_new: boolean;
  is_stale: boolean;
  has_changes: boolean;
  owned: boolean;
  target: boolean;
  notes: string | null;
  services: ServiceOut[];
  vulnerabilities: VulnOut[];
}

export interface HostListResponse {
  hosts: HostOut[];
  total: number;
}

export interface VulnInfoOut {
  cve_id: string;
  cvss: number;
  has_exploit: boolean;
  title: string;
  confidence: string;
  enables_pivot: boolean | null;
  method: string;
  port: number | null;
  in_cisa_kev: boolean;
}

export interface PathNodeOut {
  ip: string;
  hostname: string | null;
  role: string;
  segment: string | null;
  owned: boolean;
  target: boolean;
  vulns: VulnInfoOut[];
}

export interface AttackPathOut {
  nodes: PathNodeOut[];
  target_role: string;
  score: number;
  hop_count: number;
  max_cvss: number;
  has_exploits: boolean;
  attack_methods: string[];
  max_confidence: string;
}

export interface PathSummary {
  vulnerable_hosts: number;
  with_exploits: number;
  confirmed: number;
  likely: number;
  high_value_targets: Record<string, number>;
  pivot_hosts: number;
}

export interface PathsResponse {
  paths: AttackPathOut[];
  summary: PathSummary;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'host' | 'segment' | 'scan_source';
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  properties: Record<string, unknown>;
}

export interface GraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TopologySegment {
  cidr: string;
  hosts: number;
  reaches: number;
}

export interface TopologyResponse {
  segments: TopologySegment[];
  gateways: number;
  total_reach_edges: number;
}

export interface VulnListItem {
  cve_id: string;
  cvss: number | null;
  has_exploit: boolean;
  confidence: string | null;
  source: string | null;
  description: string;
  in_cisa_kev: boolean;
  cisa_kev_added: string | null;
  host_count: number;
  targets: Array<{ ip: string; port: number }>;
  ips: string[];
  sockets: string[];
}

export interface CollectHostOut {
  ip: string;
  hostname: string | null;
  port: number | null;
  role: string | null;
}

export interface CollectResponse {
  hosts: CollectHostOut[];
  filter_used: string;
  total: number;
}

export interface ImportResponse {
  hosts_imported: number;
  hosts_skipped: number;
  services_imported: number;
  segments_created: number;
  relationships_created: number;
}

export interface AnalyzeResponse {
  classification: { classified?: number; skipped?: number } | null;
  exploits: { matched?: number; hosts_matched?: number; exploits_found?: number } | null;
  scripts: { upgraded?: number } | null;
  cve_enrichment: { enriched?: number; cached?: number } | null;
  topology: { segments?: number; reach_edges?: number } | null;
  path_summary: PathSummary | null;
  ai_vulns_kept?: number;
  ai_vulns_dismissed?: number;
  ai_targets_set?: number;
  ai_cves_found?: number;
}

export type VulnStatus = 'exploited' | 'false_positive' | 'mitigated' | null;

export interface AnalysisJobStatus {
  id: string;
  status: 'running' | 'done' | 'failed';
  phase: string;
  current: number;
  total: number;
  message: string;
  nvd: boolean;
  ai: boolean;
  started_at: number;
  finished_at: number | null;
  elapsed: number;
  result: AnalyzeResponse | null;
  error: string | null;
}
