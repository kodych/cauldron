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

// Human-readable severity tier for tooltips. CVSS-3.x tiers per FIRST.
// 0 means "not scored"; we don't show severity in that case.
export function cvssSeverity(cvss: number): string {
  if (cvss >= 9.0) return 'CRITICAL';
  if (cvss >= 7.0) return 'HIGH';
  if (cvss >= 4.0) return 'MEDIUM';
  if (cvss > 0) return 'LOW';
  return 'NONE';
}

// nmap ``osfamily`` values seen in the wild → ``<Badge>``-compatible
// tone. The pentester scans the host card and immediately knows the
// platform (Windows = blue, Linux = green, etc.) without parsing the
// long ``os_name`` string. Returns ``null`` when the family is one we
// haven't styled — caller falls back to the neutral gray badge.
export function osFamilyTone(family: string | null | undefined):
  'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'purple' | 'gray' | null {
  if (!family) return null;
  const f = family.toLowerCase();
  if (f.includes('windows')) return 'blue';
  if (f.includes('linux')) return 'green';
  if (f === 'ios' || f.includes('cisco')) return 'orange';
  if (f.includes('embedded')) return 'purple';
  if (f.includes('mac os') || f.includes('macos') || f === 'darwin') return 'gray';
  if (f.includes('bsd')) return 'yellow';
  return null;
}

// Compact label for the OS-family badge. Long XML values like
// ``Mac OS X`` get shortened so the badge stays consistent in size.
export function osFamilyLabel(family: string | null | undefined): string {
  if (!family) return '';
  const f = family.toLowerCase();
  if (f.includes('windows')) return 'Windows';
  if (f.includes('linux')) return 'Linux';
  if (f === 'ios' || f.includes('cisco')) return 'IOS';
  if (f.includes('embedded')) return 'Embedded';
  if (f.includes('mac os') || f.includes('macos')) return 'macOS';
  if (f.includes('bsd')) return 'BSD';
  return family;
}
