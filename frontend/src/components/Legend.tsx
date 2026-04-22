import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { ROLE_COLORS, NODE_TYPE_COLORS } from '../utils/colors';

// Compact "at-a-glance" roster. These are the roles the operator meets on
// every engagement — keeping the default legend short means the sidebar
// bottom stays out of the way. The `Show all` toggle reveals the long tail
// (IoT, monitoring, containers, backup, etc.) for datasets where those
// roles actually appear.
const KEY_ROLES = [
  'DOMAIN_CONTROLLER',
  'DATABASE',
  'WEB_SERVER',
  'MAIL_SERVER',
  'FILE_SERVER',
  'MANAGEMENT',
  'WORKSTATION',
  'FIREWALL',
];

export function Legend() {
  const [expanded, setExpanded] = useState(false);
  const keySet = new Set(KEY_ROLES);
  const extraRoles = Object.keys(ROLE_COLORS).filter(
    (r) => !keySet.has(r) && r !== 'unknown',
  );
  const rolesShown = expanded ? [...KEY_ROLES, ...extraRoles] : KEY_ROLES;

  return (
    <div className="border-t border-gray-800 p-2.5">
      <div className="mb-1.5 flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-gray-600">
          Legend
        </p>
        {extraRoles.length > 0 && (
          <button
            onClick={() => setExpanded((v) => !v)}
            className="flex items-center gap-0.5 text-xs text-gray-600 hover:text-gray-400"
            title={expanded ? 'Collapse' : `Show ${extraRoles.length} more roles`}
          >
            {expanded ? (
              <>Less <ChevronDown size={11} /></>
            ) : (
              <>+{extraRoles.length} more <ChevronRight size={11} /></>
            )}
          </button>
        )}
      </div>
      <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        {rolesShown.map((role) => (
          <div key={role} className="flex items-center gap-1.5">
            <div
              className="h-2 w-2 rounded-full shrink-0"
              style={{ backgroundColor: ROLE_COLORS[role] }}
            />
            <span className="text-xs text-gray-500 truncate">{role}</span>
          </div>
        ))}
      </div>
      <div className="mt-1.5 flex gap-3">
        <div className="flex items-center gap-1.5">
          <div className="h-2 w-2 rounded shrink-0" style={{ backgroundColor: NODE_TYPE_COLORS.scan_source }} />
          <span className="text-xs text-gray-500">Scan Source</span>
        </div>
      </div>
    </div>
  );
}
