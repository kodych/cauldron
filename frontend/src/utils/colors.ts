// Role-based color mapping for graph nodes

export const ROLE_COLORS: Record<string, string> = {
  DOMAIN_CONTROLLER: '#ef4444',  // red — high-value target
  DATABASE:          '#e2e8f0',  // white-slate — contrast on dark bg
  WEB_SERVER:        '#3b82f6',  // blue
  MAIL_SERVER:       '#8b5cf6',  // purple
  FILE_SERVER:       '#10b981',  // green
  DNS_SERVER:        '#06b6d4',  // cyan
  PROXY:             '#f59e0b',  // amber
  FIREWALL:          '#ec4899',  // pink
  VPN:               '#14b8a6',  // teal
  PRINTER:           '#6b7280',  // gray
  MANAGEMENT:        '#f97316',  // orange — mgmt interface
  VOIP:              '#a78bfa',  // violet
  WORKSTATION:       '#64748b',  // slate
  IOT:               '#84cc16',  // lime
  MONITORING:        '#0ea5e9',  // sky
  CI_CD:             '#d946ef',  // fuchsia
  CONTAINER:         '#22d3ee',  // cyan bright
  BACKUP:            '#78716c',  // stone
  NETWORK_EQUIPMENT: '#facc15',  // yellow — routers, switches
  unknown:           '#4b5563',  // gray-600
};

export const NODE_TYPE_COLORS: Record<string, string> = {
  host:        '#6366f1',  // indigo — default for hosts without role
  segment:     '#f59e0b',  // amber
  scan_source: '#22c55e',  // green
};

export function getRoleColor(role: string): string {
  const key = role.toUpperCase();
  return ROLE_COLORS[key] || ROLE_COLORS['unknown'];
}

export function getNodeColor(type: string, role?: string): string {
  if (type === 'host' && role) {
    return getRoleColor(role);
  }
  return NODE_TYPE_COLORS[type] || '#4b5563';
}

export function getConfidenceColor(confidence: string): string {
  switch (confidence) {
    case 'confirmed': return '#ef4444';
    case 'likely':    return '#f97316';
    case 'check':     return '#6b7280';
    default:          return '#4b5563';
  }
}

export function getCvssColor(cvss: number): string {
  if (cvss >= 9.0) return '#ef4444';
  if (cvss >= 7.0) return '#f97316';
  if (cvss >= 4.0) return '#eab308';
  return '#22c55e';
}
