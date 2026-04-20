import { useState, useMemo, useCallback } from 'react';
import { Crosshair, ChevronDown, ChevronUp, AlertTriangle, Target, Unlock } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getConfidenceColor, getCvssColor, getRoleColor } from '../utils/colors';
import { formatCvss } from '../utils/format';
import type { PathsResponse, AttackPathOut } from '../types';
import { ExploitCommands } from './ExploitCommands';

type PathFilter = 'all' | 'confirmed' | 'confirmed_likely' | 'exploit' | 'target';

const PATH_FILTERS: { value: PathFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'exploit', label: 'Exploit' },
  { value: 'confirmed_likely', label: 'Confirmed+Likely' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'target', label: 'Targets' },
];

interface AttackPathsProps {
  onSelectPath?: (ips: string[] | null) => void;
  onSelectHost?: (ip: string) => void;
  refreshKey?: number;
}

export function AttackPaths({ onSelectPath, onSelectHost, refreshKey = 0 }: AttackPathsProps) {
  const [filter, setFilter] = useState<PathFilter>('all');
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  // Always fetch all paths (include check), filter client-side
  const { data, loading, error } = useApi<PathsResponse>(
    () => api.getAttackPaths({ top: 100, include_check: true }),
    [refreshKey],
  );

  const matchesFilter = useCallback((p: AttackPathOut, f: PathFilter) => {
    switch (f) {
      case 'confirmed':
        return p.nodes.some((n) => n.vulns?.some((v) => v.confidence === 'confirmed'));
      case 'confirmed_likely':
        return p.nodes.some((n) => n.vulns?.some((v) =>
          v.confidence === 'confirmed' || v.confidence === 'likely'));
      case 'exploit':
        return p.has_exploits;
      case 'target':
        // User-flagged targets + high-value roles
        return p.nodes.some((n) =>
          n.target === true ||
          (n.role && ['domain_controller', 'database', 'mail_server'].includes(n.role))
        );
      default:
        return true;
    }
  }, []);

  const filteredPaths = useMemo(
    () => data ? data.paths.filter((p) => matchesFilter(p, filter)) : [],
    [data, filter, matchesFilter],
  );

  const filterCounts = useMemo(() => {
    if (!data) return { all: 0, confirmed: 0, confirmed_likely: 0, exploit: 0, target: 0 } as Record<PathFilter, number>;
    return {
      all: data.paths.length,
      confirmed: data.paths.filter((p) => matchesFilter(p, 'confirmed')).length,
      confirmed_likely: data.paths.filter((p) => matchesFilter(p, 'confirmed_likely')).length,
      exploit: data.paths.filter((p) => matchesFilter(p, 'exploit')).length,
      target: data.paths.filter((p) => matchesFilter(p, 'target')).length,
    };
  }, [data, matchesFilter]);

  if (loading) {
    return (
      <div className="p-3 space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-16 animate-pulse rounded bg-gray-800/50" />
        ))}
      </div>
    );
  }

  if (error) {
    return <div className="p-4 text-sm text-red-400">{error}</div>;
  }

  if (!data) return null;

  return (
    <div className="flex flex-col h-full">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-1 border-b border-gray-800 px-2 py-1.5">
        <p className="text-xs text-gray-500 mr-1">{filteredPaths.length} paths</p>
        <div className="flex-1 min-w-0" />
        {PATH_FILTERS.map((f) => {
          const count = filterCounts[f.value];
          // Hide empty non-all filters to avoid dead buttons
          if (f.value !== 'all' && count === 0) return null;
          return (
            <button
              key={f.value}
              onClick={() => { setFilter(f.value); setSelectedIndex(null); onSelectPath?.(null); }}
              className={`rounded px-1.5 py-0.5 text-xs transition-colors ${
                filter === f.value
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-800 text-gray-500 hover:text-gray-300'
              }`}
              title={`${count} paths`}
            >
              {f.label} <span className="opacity-70">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Summary */}
      {data.summary && (
        <div className="grid grid-cols-3 gap-2 p-3 border-b border-gray-800">
          <div className="text-center">
            <p className="text-lg font-semibold text-indigo-400">{data.summary.vulnerable_hosts}</p>
            <p className="text-xs text-gray-600">Vulnerable</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-semibold text-red-400">{data.summary.confirmed}</p>
            <p className="text-xs text-gray-600">Confirmed</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-semibold text-orange-400">{data.summary.likely}</p>
            <p className="text-xs text-gray-600">Likely</p>
          </div>
        </div>
      )}

      {/* Path list */}
      <div className="flex-1 overflow-y-auto">
        {filteredPaths.length === 0 ? (
          <div className="p-4 text-center text-xs text-gray-600">
            {filter === 'all' ? 'No attack paths found' : `No paths matching "${filter}" filter`}
          </div>
        ) : (
          filteredPaths.map((path, i) => (
            <PathCard key={i} path={path} index={i + 1} selected={selectedIndex === i}
              onSelect={() => {
                if (selectedIndex === i) {
                  setSelectedIndex(null);
                  onSelectPath?.(null);
                } else {
                  setSelectedIndex(i);
                  const ips = path.nodes.map((n) => n.ip);
                  onSelectPath?.(ips);
                }
              }}
              onSelectHost={onSelectHost}
            />
          ))
        )}
      </div>
    </div>
  );
}

function PathCard({ path, index, selected, onSelect, onSelectHost }: {
  path: AttackPathOut; index: number; selected?: boolean; onSelect?: () => void;
  onSelectHost?: (ip: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);


  return (
    <div className={`border-b border-gray-800/50 ${selected ? 'bg-indigo-950/30' : ''}`}>
      <button
        onClick={() => { setExpanded(!expanded); onSelect?.(); }}
        className="w-full px-3 py-2.5 text-left hover:bg-gray-800/30 transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-gray-600 w-5">#{index}</span>
          <div
            className="h-2 w-2 rounded-full shrink-0"
            style={{ backgroundColor: getConfidenceColor(path.max_confidence) }}
          />
          <div className="flex-1 min-w-0">
            <p className="text-xs text-gray-200 truncate">
              {path.nodes.map((n) => n.ip).join(' → ')}
            </p>
            <div className="flex items-center gap-2 mt-0.5">
              <span
                className="text-xs"
                style={{ color: getRoleColor(path.target_role) }}
              >
                {path.target_role}
              </span>
              <span className="text-xs text-gray-600">
                {path.hop_count} hop{path.hop_count !== 1 ? 's' : ''}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <span
              className="text-xs font-mono font-semibold"
              style={{ color: path.score >= 50 ? '#ef4444' : path.score >= 25 ? '#f97316' : '#6b7280' }}
            >
              {path.score.toFixed(1)}
            </span>
            {path.has_exploits && (
              <AlertTriangle size={12} className="text-red-400" />
            )}
            {expanded ? <ChevronUp size={14} className="text-gray-600" /> : <ChevronDown size={14} className="text-gray-600" />}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2">
          {/* Attack methods */}
          {path.attack_methods.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {path.attack_methods.map((m) => (
                <span key={m} className="rounded bg-gray-800 px-1.5 py-0.5 text-xs text-gray-400">
                  {m}
                </span>
              ))}
            </div>
          )}

          {/* Path nodes */}
          {path.nodes.map((node, ni) => (
            <div key={node.ip} className="relative pl-4">
              {/* Connector line */}
              {ni < path.nodes.length - 1 && (
                <div className="absolute left-[5px] top-4 bottom-0 w-px bg-gray-700" />
              )}
              <div className="absolute left-0 top-1.5 h-2.5 w-2.5 rounded-full bg-gray-700 border-2 border-gray-900" />

              <div className="text-xs">
                <p className="font-mono">
                  {node.role !== 'scan_source' && onSelectHost ? (
                    <button
                      onClick={(e) => { e.stopPropagation(); onSelectHost(node.ip); }}
                      className="text-gray-300 hover:text-indigo-400 hover:underline transition-colors"
                    >
                      {node.ip}
                    </button>
                  ) : (
                    <span className="text-gray-300">{node.ip}</span>
                  )}
                  {node.hostname && <span className="text-gray-600 font-sans ml-1">({node.hostname})</span>}
                </p>
                <p className="text-gray-600 flex items-center gap-1.5">
                  <span>{node.role} {node.segment && `· ${node.segment}`}</span>
                  {node.owned && (
                    <span className="rounded bg-green-900/30 px-1 py-0 text-green-400 font-semibold flex items-center gap-0.5">
                      <Unlock size={9} /> OWNED
                    </span>
                  )}
                  {node.target && (
                    <span className="rounded bg-red-900/30 px-1 py-0 text-red-400 font-semibold flex items-center gap-0.5">
                      <Target size={9} /> TARGET
                    </span>
                  )}
                </p>
                {node.vulns.map((v) => (
                  <div key={v.cve_id + ':' + (v.port ?? '')} className="mt-0.5 ml-2">
                    <div className="flex items-start gap-1.5">
                      <Crosshair size={10} className="shrink-0 mt-0.5" style={{ color: v.cvss > 0 ? getCvssColor(v.cvss) : getConfidenceColor(v.confidence) }} />
                      <div className="min-w-0 flex-1">
                        {v.port != null && (
                          <span className="font-mono text-gray-500 mr-1">:{v.port}</span>
                        )}
                        <span className="text-gray-400">{v.cve_id}</span>
                        {v.title && <span className="text-gray-500 ml-1">— {v.title}</span>}
                        <span className="ml-1 font-mono" style={{ color: v.cvss > 0 ? getCvssColor(v.cvss) : '#6b7280' }}>
                          [{formatCvss(v.cvss)}]
                        </span>
                        <span
                          className="ml-1 font-medium"
                          style={{ color: getConfidenceColor(v.confidence) }}
                        >
                          {v.confidence}
                        </span>
                        {v.has_exploit && (
                          <span className="ml-1 rounded px-1 py-0 bg-red-900/30 text-red-400 font-semibold text-xs">
                            EXPLOIT
                          </span>
                        )}
                      </div>
                    </div>
                    {v.port != null && (v.has_exploit || v.confidence === 'confirmed' || v.confidence === 'likely') && (
                      <div className="mt-0.5 ml-4">
                        <ExploitCommands hostIp={node.ip} port={v.port} vulnId={v.cve_id} compact />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}

          {/* Score */}
          <div className="flex justify-end">
            <span className="text-xs text-gray-600">
              Score: <span className="text-gray-400 font-mono">{path.score.toFixed(1)}</span>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
