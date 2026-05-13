// Shared formatting utilities

/** Format CVSS score: show "N/A" when score is 0 or missing */
export function formatCvss(cvss: number): string {
  if (!cvss || cvss <= 0) return 'N/A';
  return cvss.toFixed(1);
}

/** Roles that are high-value pentest targets — get larger nodes */
export const HIGH_VALUE_ROLES = new Set([
  'DOMAIN_CONTROLLER',
  'DATABASE',
  'MANAGEMENT',
  'MAIL_SERVER',
  'BACKUP',
  'CI_CD',
]);

// Vulnerability ``source`` can carry multiple values joined by ``+`` when
// more than one channel detected the same CVE (e.g. ``exploit_db+nvd`` for
// a local rule that NVD's CPE pipeline also returned). Split + filter so
// the caller can render one badge per source and treat missing/unknown
// sources uniformly.
export function parseSources(source: string | null | undefined): string[] {
  if (!source) return [];
  return source.split('+').map((s) => s.trim()).filter(Boolean);
}

/** Per-source display label. Unknown values render as-is. */
export function sourceLabel(token: string): string {
  switch (token) {
    case 'ai': return 'AI';
    case 'exploit_db': return 'DB';
    case 'nvd': return 'NVD';
    default: return token;
  }
}

/** Per-source colour classes for the small inline badge. */
export function sourceBadgeClass(token: string): string {
  switch (token) {
    case 'ai': return 'bg-purple-900/30 text-purple-400';
    case 'exploit_db': return 'bg-amber-900/30 text-amber-400';
    case 'nvd': return 'bg-cyan-900/30 text-cyan-400';
    default: return 'bg-gray-700 text-gray-400';
  }
}

