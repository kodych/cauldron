import { ROLE_COLORS, NODE_TYPE_COLORS } from '../utils/colors';

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
  return (
    <div className="border-t border-gray-800 p-2.5">
      <p className="mb-1.5 text-xs font-medium uppercase tracking-wider text-gray-600">
        Legend
      </p>
      <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        {KEY_ROLES.map((role) => (
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
