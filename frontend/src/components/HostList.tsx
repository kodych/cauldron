import { useState, useMemo } from 'react';
import { Search, ChevronDown, ChevronUp, X } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getRoleColor, getCvssColor, getConfidenceColor } from '../utils/colors';
import type { HostListResponse, HostOut } from '../types';

interface Props {
  onSelectHost: (ip: string | null) => void;
  selectedHost: string | null;
  refreshKey?: number;
}

export function HostList({ onSelectHost, selectedHost, refreshKey = 0 }: Props) {
  const [search, setSearch] = useState('');
  const { data, loading, error } = useApi<HostListResponse>(
    () => api.getHosts({ limit: 500 }),
    [refreshKey],
  );

  if (loading) {
    return (
      <div className="p-3 space-y-2">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="h-10 animate-pulse rounded bg-gray-800/50" />
        ))}
      </div>
    );
  }

  if (error) {
    return <div className="p-4 text-sm text-red-400">{error}</div>;
  }

  if (!data) return null;

  const filtered = data.hosts.filter((h) => {
    const q = search.toLowerCase();
    return (
      h.ip.includes(q) ||
      (h.hostname?.toLowerCase().includes(q)) ||
      h.role.toLowerCase().includes(q) ||
      (h.notes?.toLowerCase().includes(q)) ||
      h.services.some(
        (s) =>
          (s.product?.toLowerCase().includes(q)) ||
          (s.name?.toLowerCase().includes(q)) ||
          (s.notes?.toLowerCase().includes(q)),
      ) ||
      h.vulnerabilities.some((v) => v.cve_id.toLowerCase().includes(q))
    );
  });

  return (
    <div className="flex flex-col h-full">
      {/* Search */}
      <div className="p-2 border-b border-gray-800">
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-2 text-gray-500" />
          <input
            type="text"
            placeholder="Filter hosts, CVE, product, notes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded bg-gray-800 py-1.5 pl-8 pr-7 text-xs text-gray-200 placeholder-gray-600 outline-none focus:ring-1 focus:ring-indigo-500"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-1.5 top-1.5 rounded p-0.5 text-gray-500 hover:bg-gray-700 hover:text-gray-200"
              title="Clear search"
            >
              <X size={12} />
            </button>
          )}
        </div>
        <p className="mt-1.5 text-xs text-gray-600">
          {filtered.length} of {data.total} hosts
        </p>
      </div>

      {/* Host list */}
      <div className="flex-1 overflow-y-auto">
        {filtered.map((host) => (
          <HostRow
            key={host.ip}
            host={host}
            selected={selectedHost === host.ip}
            onClick={() => onSelectHost(selectedHost === host.ip ? null : host.ip)}
          />
        ))}
      </div>
    </div>
  );
}

function HostRow({ host, selected, onClick }: { host: HostOut; selected: boolean; onClick: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const activeVulns = host.vulnerabilities.filter((v) => v.checked_status !== 'false_positive');
  const vulnCount = activeVulns.length;
  const maxCvss = vulnCount > 0 ? Math.max(...activeVulns.map((v) => v.cvss || 0)) : 0;


  return (
    <div
      className={`border-b border-gray-800/50 transition-colors ${
        selected ? 'bg-indigo-950/30' : 'hover:bg-gray-800/30'
      } ${host.is_stale ? 'opacity-40' : ''}`}
    >
      <button
        onClick={onClick}
        className="flex w-full items-center gap-2 px-3 py-2 text-left"
      >
        <div
          className="h-2.5 w-2.5 rounded-full shrink-0"
          style={{ backgroundColor: getRoleColor(host.role) }}
        />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-mono text-gray-200 truncate">
            {host.ip}
            {host.hostname && (
              <span className="ml-1.5 text-gray-500 font-sans">({host.hostname})</span>
            )}
          </p>
          <p className="text-xs text-gray-600">{host.role}</p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {vulnCount > 0 && (
            <span
              className="rounded px-1.5 py-0.5 text-xs font-mono"
              style={{
                color: getCvssColor(maxCvss),
                backgroundColor: getCvssColor(maxCvss) + '18',
              }}
            >
              {vulnCount}V
            </span>
          )}
          {host.is_new && (
            <span className="rounded bg-green-900/30 px-1.5 py-0.5 text-xs text-green-400 font-semibold">
              NEW
            </span>
          )}
          {host.is_stale && (
            <span className="rounded bg-gray-700 px-1.5 py-0.5 text-xs text-gray-500 font-semibold">
              GONE
            </span>
          )}
          {!host.is_new && !host.is_stale && host.has_changes && (
            <span className="rounded bg-yellow-900/30 px-1.5 py-0.5 text-xs text-yellow-400 font-semibold">
              CHANGED
            </span>
          )}
          {vulnCount > 0 && activeVulns.some((v) => v.has_exploit) ? (
            <span className="rounded bg-red-900/30 px-1.5 py-0.5 text-xs text-red-400 font-semibold">
              EXPLOIT
            </span>
          ) : vulnCount > 0 ? (
            <span className="rounded bg-purple-900/30 px-1.5 py-0.5 text-xs text-purple-400">
              VULN
            </span>
          ) : null}
          {host.owned && (
            <span className="rounded bg-green-900/30 px-1.5 py-0.5 text-xs text-green-400 font-semibold">
              OWNED
            </span>
          )}
          {host.target && (
            <span className="rounded bg-red-900/30 px-1.5 py-0.5 text-xs text-red-400 font-semibold">
              TARGET
            </span>
          )}
          <button
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
            className="text-gray-600 hover:text-gray-400"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-3 pb-2 space-y-2">
          {host.os_name && (
            <p className="text-xs text-gray-500">OS: {host.os_name}</p>
          )}


          {/* Services */}
          {host.services.length > 0 && (
            <HostServices services={host.services} vulns={host.vulnerabilities} />
          )}

          {/* Vulnerabilities */}
          {host.vulnerabilities.length > 0 && (
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">Vulnerabilities</p>
              <div className="space-y-0.5">
                {host.vulnerabilities.map((v) => (
                  <div key={v.cve_id} className="flex items-center gap-2 text-xs">
                    {v.port != null && (
                      <span className="font-mono text-gray-500 shrink-0 w-10 text-right">:{v.port}</span>
                    )}
                    {v.cvss > 0 && (
                      <span
                        className="font-mono shrink-0"
                        style={{ color: getCvssColor(v.cvss) }}
                      >
                        {v.cvss.toFixed(1)}
                      </span>
                    )}
                    <span className="text-gray-400 truncate">{v.cve_id}</span>
                    <span
                      className="shrink-0"
                      style={{ color: getConfidenceColor(v.confidence) }}
                    >
                      {v.confidence || 'check'}
                    </span>
                    {v.has_exploit && (
                      <span className="shrink-0 rounded px-1 py-0 bg-red-900/30 text-red-400 font-semibold">
                        EXPLOIT
                      </span>
                    )}
                    {v.source && (
                      <span className={`shrink-0 rounded px-1 py-0 ${
                        v.source === 'ai' ? 'bg-purple-900/30 text-purple-400' :
                        v.source === 'exploit_db' ? 'bg-amber-900/30 text-amber-400' :
                        v.source === 'nvd' ? 'bg-cyan-900/30 text-cyan-400' :
                        'bg-gray-700 text-gray-400'
                      }`}>
                        {v.source === 'ai' ? 'AI' : v.source === 'exploit_db' ? 'DB' : v.source === 'nvd' ? 'NVD' : v.source}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function HostServices({ services, vulns }: { services: HostOut['services']; vulns: HostOut['vulnerabilities'] }) {
  const portCvssMap = useMemo(() => {
    const map = new Map<number, number>();
    for (const v of vulns) {
      if (v.port != null) {
        map.set(v.port, Math.max(map.get(v.port) || 0, v.cvss || 0));
      }
    }
    return map;
  }, [vulns]);

  return (
    <div>
      <p className="text-xs font-medium text-gray-500 mb-1">Services</p>
      <div className="space-y-0.5">
        {services.map((s) => {
          const cvss = portCvssMap.get(s.port) || 0;
          const color = cvss > 0 ? getCvssColor(cvss) : '#60a5fa';
          return (
            <div key={`${s.port}/${s.protocol}`} className={`flex items-center gap-2 text-xs ${s.is_stale ? 'opacity-40 line-through' : ''}`}>
              <span className="font-mono w-14 text-right" style={{ color }}>{s.port}/{s.protocol}</span>
              <span className="text-gray-400 truncate">
                {s.name}{s.product && ` — ${s.product}`}{s.version && ` ${s.version}`}
              </span>
              {s.is_new && (
                <span className="shrink-0 rounded px-1 py-0 bg-green-900/30 text-green-400 font-semibold">NEW</span>
              )}
              {s.is_stale && (
                <span className="shrink-0 rounded px-1 py-0 bg-gray-700 text-gray-500">GONE</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
