import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getRoleColor } from '../utils/colors';
import type { StatsResponse } from '../types';

export function StatsPanel({ refreshKey = 0 }: { refreshKey?: number }) {
  const { data: stats, loading, error } = useApi<StatsResponse>(() => api.getStats(), [refreshKey]);

  // Skeleton only on initial load. Background refetches (after import
  // / analysis bump refreshKey) keep the previous numbers visible so
  // the dashboard doesn't blank out mid-action.
  if (loading && !stats) {
    return <LoadingState />;
  }

  if (error) {
    return (
      <div className="p-4">
        <p className="text-sm text-red-400">{error}</p>
      </div>
    );
  }

  if (!stats) return null;

  const statCards = [
    { label: 'Hosts', value: stats.hosts, color: 'text-steel-400' },
    { label: 'Services', value: stats.services, color: 'text-blue-400' },
    { label: 'Vulnerabilities', value: stats.vulnerabilities, color: 'text-red-400' },
    { label: 'Findings', value: stats.findings ?? 0, color: 'text-orange-400' },
    { label: 'Scan Sources', value: stats.scan_sources, color: 'text-green-400' },
    { label: 'Segments', value: stats.segments, color: 'text-cyan-400' },
  ];

  const sortedRoles = Object.entries(stats.roles).sort(([, a], [, b]) => b - a);

  return (
    <div className="p-3 space-y-4">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-2">
        {statCards.map(({ label, value, color }) => (
          <div key={label} className="rounded-lg bg-gray-800/50 p-2.5">
            <p className="text-xs text-gray-500">{label}</p>
            <p className={`text-lg font-semibold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Role distribution */}
      {sortedRoles.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-medium uppercase tracking-wider text-gray-500">
            Host Roles
          </h3>
          <div className="space-y-1.5">
            {sortedRoles.map(([role, count]) => {
              const pct = Math.round((count / stats.hosts) * 100);
              return (
                <div key={role} className="flex items-center gap-2">
                  <div
                    className="h-2.5 w-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: getRoleColor(role) }}
                  />
                  <span className="text-xs text-gray-300 flex-1 truncate">{role}</span>
                  <span className="text-xs text-gray-500">{count}</span>
                  <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${pct}%`,
                        backgroundColor: getRoleColor(role),
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

    </div>
  );
}

function LoadingState() {
  return (
    <div className="p-3 space-y-2">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="h-12 animate-pulse rounded-lg bg-gray-800/50" />
      ))}
    </div>
  );
}
