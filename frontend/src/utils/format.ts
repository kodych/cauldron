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

