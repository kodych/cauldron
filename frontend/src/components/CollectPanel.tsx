import { useState, useCallback } from 'react';
import { Clipboard, Check, Terminal, Filter, Hash } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import type { CollectResponse } from '../types';

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
];

export function CollectPanel() {
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [customPort, setCustomPort] = useState('');
  const [copiedType, setCopiedType] = useState<'ip' | 'socket' | null>(null);
  const [result, setResult] = useState<CollectResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

      {!result && !loading && !error && (
        <div className="p-4 text-center text-xs text-gray-600">
          Select a filter to collect targets
        </div>
      )}
    </div>
  );
}
