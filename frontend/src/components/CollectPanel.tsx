import { useState, useCallback, useEffect, useRef } from 'react';
import { Clipboard, Check, Terminal, Filter, Hash, Bug, ChevronDown, ChevronUp, Flame } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getCvssColor } from '../utils/colors';
import type { CollectResponse, VulnListItem } from '../types';
import { Badge } from './Badge';

const QUICK_FILTERS = [
  { name: 'smb', label: 'SMB', desc: 'Port 445' },
  { name: 'rdp', label: 'RDP', desc: 'Port 3389' },
  { name: 'ssh', label: 'SSH', desc: 'Port 22' },
  { name: 'http', label: 'HTTP', desc: 'Web servers' },
  { name: 'mssql', label: 'MSSQL', desc: 'Port 1433' },
  { name: 'mysql', label: 'MySQL', desc: 'Port 3306' },
  { name: 'ftp', label: 'FTP', desc: 'Port 21' },
  { name: 'vuln', label: 'Vuln', desc: 'Any vulnerability' },
  { name: 'exploitable', label: 'Exploitable', desc: 'Has exploit' },
  { name: 'rce', label: 'RCE', desc: 'Remote code exec' },
  { name: 'dc', label: 'DC', desc: 'Domain controllers' },
  { name: 'db', label: 'DB', desc: 'Databases' },
  { name: 'brute', label: 'Brute', desc: 'Bruteforceable services' },
];

interface CollectPanelProps {
  refreshKey?: number;
}

export function CollectPanel({ refreshKey = 0 }: CollectPanelProps) {
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [customPort, setCustomPort] = useState('');
  const [copiedType, setCopiedType] = useState<'ip' | 'socket' | null>(null);
  const [result, setResult] = useState<CollectResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showVulns, setShowVulns] = useState(false);
  const { data: vulnData } = useApi<{ vulns: VulnListItem[]; total: number }>(
    () => showVulns ? api.getVulns() : Promise.resolve({ vulns: [], total: 0 }),
    [showVulns, refreshKey],
  );

  const runCollect = useCallback(async (filter?: string, port?: number) => {
    setLoading(true);
    setError(null);
    setCopiedType(null);
    try {
      const params: { filter?: string; port?: number } = {};
      if (filter) params.filter = filter;
      if (port) params.port = port;
      const data = await api.getCollect(params);
      setResult(data);
      setActiveFilter(filter || `port:${port}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed');
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // Refresh active filter when data changes elsewhere (e.g. FP toggle)
  const lastFilterRef = useRef<string | null>(null);
  lastFilterRef.current = activeFilter;
  useEffect(() => {
    if (refreshKey === 0) return;
    const f = lastFilterRef.current;
    if (!f) return;
    if (f.startsWith('port:')) {
      const p = parseInt(f.slice(5));
      if (p > 0) runCollect(undefined, p);
    } else {
      runCollect(f);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey]);

  const handleFilterClick = useCallback((name: string) => {
    runCollect(name);
  }, [runCollect]);

  const handleCustomPort = useCallback(() => {
    const port = parseInt(customPort);
    if (port > 0 && port <= 65535) {
      runCollect(undefined, port);
    }
  }, [customPort, runCollect]);

  const copyToClipboard = useCallback(async () => {
    if (!result) return;
    const text = result.hosts.map((h) => h.ip).join('\n');
    await navigator.clipboard.writeText(text);
    setCopiedType('ip');
    setTimeout(() => setCopiedType(null), 2000);
  }, [result]);

  const copyWithPorts = useCallback(async () => {
    if (!result) return;
    const text = result.hosts
      .map((h) => h.port ? `${h.ip}:${h.port}` : h.ip)
      .join('\n');
    await navigator.clipboard.writeText(text);
    setCopiedType('socket');
    setTimeout(() => setCopiedType(null), 2000);
  }, [result]);

  return (
    <div className="flex flex-col h-full">
      {/* Filter grid */}
      <div className="p-2 border-b border-gray-800">
        <div className="flex items-center gap-1.5 mb-2">
          <Filter size={13} className="text-indigo-400" />
          <span className="text-xs font-medium text-gray-400">Quick Filters</span>
        </div>
        <div className="grid grid-cols-4 gap-1">
          {QUICK_FILTERS.map((f) => (
            <button
              key={f.name}
              onClick={() => handleFilterClick(f.name)}
              disabled={loading}
              className={`rounded px-1.5 py-1 text-xs transition-colors ${
                activeFilter === f.name
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-200'
              }`}
              title={f.desc}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Custom port */}
        <div className="flex items-center gap-1.5 mt-2">
          <Hash size={13} className="text-gray-500" />
          <input
            type="number"
            placeholder="Custom port"
            value={customPort}
            onChange={(e) => setCustomPort(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCustomPort()}
            className="flex-1 rounded bg-gray-800 px-2 py-1 text-xs text-gray-200 placeholder-gray-600 outline-none focus:ring-1 focus:ring-indigo-500"
          />
          <button
            onClick={handleCustomPort}
            disabled={loading || !customPort}
            className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200 disabled:opacity-50"
          >
            Go
          </button>
        </div>
      </div>

      {/* By Vulnerability section */}
      <div className="p-2 border-b border-gray-800">
        <button
          onClick={() => setShowVulns(!showVulns)}
          className="flex items-center gap-1.5 w-full text-left"
        >
          <Bug size={13} className="text-red-400" />
          <span className="text-xs font-medium text-gray-400 flex-1">By Vulnerability</span>
          {showVulns ? <ChevronUp size={13} className="text-gray-600" /> : <ChevronDown size={13} className="text-gray-600" />}
        </button>

        {showVulns && vulnData && vulnData.vulns.length > 0 && (
          <div className="mt-2 space-y-0.5 max-h-[50vh] overflow-y-auto">
            {vulnData.vulns.map((v) => (
              <VulnCollectRow key={v.cve_id} vuln={v} />
            ))}
          </div>
        )}
        {showVulns && vulnData && vulnData.vulns.length === 0 && (
          <p className="mt-2 text-xs text-gray-600">No vulnerabilities found. Run analysis first.</p>
        )}
      </div>

      {/* Results */}
      {loading && (
        <div className="p-4 text-center">
          <div className="h-6 w-6 animate-spin rounded-full border-2 border-indigo-400 border-t-transparent mx-auto" />
        </div>
      )}

      {error && (
        <div className="p-3 text-xs text-red-400">{error}</div>
      )}

      {result && !loading && (
        <div className="flex flex-col flex-1 min-h-0">
          {/* Result header */}
          <div className="flex items-center justify-between px-3 py-2 border-b border-gray-800">
            <div className="flex items-center gap-2">
              <Terminal size={13} className="text-green-400" />
              <span className="text-xs text-gray-400">
                {result.total} target{result.total !== 1 ? 's' : ''}
              </span>
              <span className="text-xs text-gray-600">({result.filter_used})</span>
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={copyToClipboard}
                className="flex items-center gap-1 rounded bg-gray-800 px-2 py-1 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200"
                title="Copy IPs"
              >
                {copiedType === 'ip' ? <Check size={12} className="text-green-400" /> : <Clipboard size={12} />}
                IP
              </button>
              <button
                onClick={copyWithPorts}
                className="flex items-center gap-1 rounded bg-gray-800 px-2 py-1 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200"
                title="Copy Socket"
              >
                {copiedType === 'socket' ? <Check size={12} className="text-green-400" /> : <Clipboard size={12} />}
                Socket
              </button>
            </div>
          </div>

          {/* IP list */}
          <div className="flex-1 overflow-y-auto font-mono text-xs">
            {result.hosts.map((h) => (
              <div key={`${h.ip}:${h.port}`} className="flex items-center px-3 py-0.5 hover:bg-gray-800/30">
                <span className="text-green-400 flex-1">{h.ip}</span>
                {h.port && <span className="text-gray-600">:{h.port}</span>}
                {h.role && <span className="text-gray-600 ml-2 text-right w-20 truncate">{h.role}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {!result && !loading && !error && !showVulns && (
        <div className="p-4 text-center text-xs text-gray-600">
          Select a filter to collect targets
        </div>
      )}
    </div>
  );
}


function PortGroupedTargets({ targets }: { targets: Array<{ ip: string; port: number }> }) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Group by port
  const groups = new Map<number, string[]>();
  for (const t of targets) {
    const list = groups.get(t.port) || [];
    if (!list.includes(t.ip)) list.push(t.ip);
    groups.set(t.port, list);
  }
  const sortedPorts = [...groups.keys()].sort((a, b) => a - b);

  const copyList = useCallback(async (text: string, key: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }, []);

  return (
    <div className="font-mono text-xs space-y-1">
      {sortedPorts.map((port) => {
        const ips = groups.get(port) || [];
        return (
          <div key={port}>
            <div className="flex items-center gap-1.5 mb-0.5">
              <span className="text-gray-500">:{port}</span>
              <span className="text-gray-700">({ips.length})</span>
              <div className="flex-1" />
              <button
                onClick={() => copyList(ips.join('\n'), `ip:${port}`)}
                className="flex items-center gap-0.5 rounded bg-gray-800 px-1 py-0 text-gray-600 hover:text-gray-300"
                title={`Copy ${ips.length} IPs`}
              >
                {copiedKey === `ip:${port}` ? <Check size={9} className="text-green-400" /> : <Clipboard size={9} />}
                <span className="text-[10px]">IP</span>
              </button>
              <button
                onClick={() => copyList(ips.map(ip => `${ip}:${port}`).join('\n'), `sock:${port}`)}
                className="flex items-center gap-0.5 rounded bg-gray-800 px-1 py-0 text-gray-600 hover:text-gray-300"
                title={`Copy ${ips.length} IP:${port} sockets`}
              >
                {copiedKey === `sock:${port}` ? <Check size={9} className="text-green-400" /> : <Clipboard size={9} />}
                <span className="text-[10px]">Socket</span>
              </button>
            </div>
            {ips.map((ip) => (
              <div key={ip} className="pl-4 text-green-400 py-0 hover:bg-gray-800/30">{ip}</div>
            ))}
          </div>
        );
      })}
    </div>
  );
}


function VulnCollectRow({ vuln }: { vuln: VulnListItem }) {
  const [expanded, setExpanded] = useState(false);

  const cvssColor = vuln.cvss ? getCvssColor(vuln.cvss) : '#6b7280';

  return (
    <div className="rounded bg-gray-800/30">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-1.5 px-2 py-1.5 text-left hover:bg-gray-800/50 transition-colors"
      >
        <span className="text-xs font-mono font-semibold" style={{ color: cvssColor }}>
          {vuln.cvss?.toFixed(1) || 'N/A'}
        </span>
        <span className="text-xs text-gray-300 flex-1 truncate">{vuln.cve_id}</span>
        {vuln.in_cisa_kev && (
          <span className="shrink-0">
            <Badge tone="orange" strong title="CISA Known Exploited Vulnerability">
              <Flame size={10} />
            </Badge>
          </span>
        )}
        {vuln.has_exploit && !vuln.in_cisa_kev && (
          <span className="shrink-0"><Badge tone="red">EXP</Badge></span>
        )}
        <span className="text-xs text-gray-500">{vuln.host_count}h</span>
        {expanded ? <ChevronUp size={11} className="text-gray-600" /> : <ChevronDown size={11} className="text-gray-600" />}
      </button>

      {expanded && (
        <div className="px-2 pb-2">
          {vuln.description && (
            <p className="text-xs text-gray-500 mb-1.5">{vuln.description}</p>
          )}
          <div className="flex items-center gap-1 mb-1">
            <span className="text-xs text-gray-600">{vuln.source}</span>
            <span className="text-xs text-gray-700">·</span>
            <span className="text-xs text-gray-600">{vuln.confidence}</span>
          </div>
          <PortGroupedTargets targets={vuln.targets} />
        </div>
      )}
    </div>
  );
}
