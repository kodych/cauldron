import { useRef, useState } from 'react';
import { ChevronDown, ChevronRight, Info } from 'lucide-react';
import { ROLE_COLORS } from '../utils/colors';

// Legend floats as a chip in the graph canvas's top-right controls bar.
// Collapsed it is a single Info-icon button. On hover the full panel
// expands below — role colour palette plus State markers — without
// reserving any real estate on the sidebar. Graph-view-only makes
// sense because role colours and state glyphs only apply on the graph.
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
  const [open, setOpen] = useState(false);
  // Close timer keeps the panel visible for ~150ms after the mouse
  // leaves either the trigger or the panel. A pure CSS group-hover
  // flicker-closed the menu whenever the pointer crossed the 4px gap
  // between trigger and panel — making the "+N more" button
  // unreachable because the panel vanished mid-travel.
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const show = () => {
    if (closeTimer.current) {
      clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
    setOpen(true);
  };
  const scheduleHide = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current);
    closeTimer.current = setTimeout(() => setOpen(false), 150);
  };

  const keySet = new Set(KEY_ROLES);
  const extraRoles = Object.keys(ROLE_COLORS).filter(
    (r) => !keySet.has(r) && r !== 'unknown',
  );
  const rolesShown = expanded ? [...KEY_ROLES, ...extraRoles] : KEY_ROLES;

  return (
    <div
      className="relative"
      onMouseEnter={show}
      onMouseLeave={scheduleHide}
      onFocus={show}
      onBlur={scheduleHide}
    >
      {/* Trigger chip — styled to match the adjacent Filters / All /
          Attack buttons in the graph canvas top-right control bar. */}
      <button
        type="button"
        className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs border bg-gray-900/90 border-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
      >
        <Info size={13} />
        Legend
      </button>

      {/* Expanded panel. Only rendered when open so it cannot catch
          clicks or flash when hidden. Anchored to the right edge so
          the flyout stays inside the viewport regardless of window
          width. The panel is a DOM child of the wrapper, so hovering
          it cancels the wrapper's scheduled close. */}
      {open && (
      <div
        className="absolute right-0 top-full mt-1 w-64 rounded-lg bg-gray-900/95 border border-gray-700 p-3 shadow-xl backdrop-blur z-50"
      >
        <div className="mb-1.5 flex items-center justify-between">
          <p className="text-xs font-medium uppercase tracking-wider text-gray-500">
            Roles
          </p>
          {extraRoles.length > 0 && (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="flex items-center gap-0.5 text-xs text-gray-500 hover:text-gray-300"
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
              <span className="text-xs text-gray-400 truncate">{role}</span>
            </div>
          ))}
        </div>

        <div className="mt-2 pt-2 border-t border-gray-800/60">
          <p className="mb-1 text-xs font-medium uppercase tracking-wider text-gray-500">State</p>
          <div className="space-y-0.5">
            <div className="flex items-center gap-1.5">
              <span className="shrink-0 w-4 text-center text-sm leading-none">💀</span>
              <span className="text-xs text-gray-400">Owned (compromised)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="shrink-0 w-4 text-center text-sm leading-none">🎯</span>
              <span className="text-xs text-gray-400">Target (flagged)</span>
            </div>
            <div className="shrink-0 w-full border-t border-gray-800/60 my-1" />
            <div className="flex items-center gap-1.5">
              <span className="shrink-0 w-4 text-center text-sm leading-none">⭐</span>
              <span className="text-xs text-gray-400">New since last scan</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="shrink-0 w-4 text-center text-sm leading-none">⚠️</span>
              <span className="text-xs text-gray-400">Changed since last scan</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="shrink-0 w-4 text-center text-sm leading-none">❌</span>
              <span className="text-xs text-gray-400">Gone since last scan</span>
            </div>
          </div>
        </div>
      </div>
      )}
    </div>
  );
}
