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

// Scan-source palette: each scan position gets a distinct edge colour,
// so the kill chain "this segment was unlocked from THIS pivot" is
// readable at a glance on multi-source engagements. Order matches
// scan first_seen ascending: the earliest scan source paints lime,
// the first pivot paints cyan, etc.
//
// Red is deliberately absent — it's reserved for attack-chain overlay
// on top of these. The palette is colour-blind-aware (no
// indistinguishable green/red pairs).
export const SCAN_SOURCE_PALETTE: readonly string[] = [
  '#84cc16',  // lime — initial scan position
  '#06b6d4',  // cyan — first pivot
  '#a855f7',  // purple — second pivot
  '#f97316',  // orange — third pivot
  '#92400e',  // amber-800 (brown) — fourth pivot
];

// Beyond the palette length, sources fall back to a neutral colour —
// engagements with more than 5 pivot positions are unusual, and the
// operator can still tell sources apart via the scan-source detail
// panel. The fallback is brighter than the topology default so the
// edges don't disappear entirely.
export const SCAN_SOURCE_FALLBACK = '#64748b';  // slate-500

export function getScanSourceColor(index: number): string {
  if (index < 0) return SCAN_SOURCE_FALLBACK;
  return SCAN_SOURCE_PALETTE[index] ?? SCAN_SOURCE_FALLBACK;
}


export const NODE_TYPE_COLORS: Record<string, string> = {
  host:        '#6366f1',  // indigo — default for hosts without role
  segment:     '#f59e0b',  // amber
  // Standalone scan source = pentester's box at the start of the kill
  // chain. Red mirrors the DC role color: the engagement starts at
  // a red node (operator's kali) and ends at a red node (compromised
  // DC). The 💀 marker + IP-only label + small size disambiguate them
  // at a glance. Pivot hosts that double as scan sources keep their
  // role color instead — they're not "scan source" type, they're
  // regular hosts merged with the source.
  scan_source: '#ef4444',  // red — kali-on-the-attack-side bookend
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
