import { useState, useCallback, useMemo, useRef } from 'react';
import { ArrowLeft, Shield, Server, Bug, ChevronDown, ChevronUp, Check, X, ExternalLink, Key, MessageSquare } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getRoleColor, getConfidenceColor, getCvssColor } from '../utils/colors';
import type { HostOut, VulnOut, VulnStatus } from '../types';

interface Props {
  ip: string;
  onBack: () => void;
}

const STATUS_OPTIONS: { value: VulnStatus; label: string; color: string; icon: React.ReactNode }[] = [
  { value: 'exploited', label: 'Exploited', color: '#22c55e', icon: <Check size={10} /> },
  { value: 'false_positive', label: 'False Positive', color: '#6b7280', icon: <X size={10} /> },
  { value: 'mitigated', label: 'Mitigated', color: '#3b82f6', icon: <Shield size={10} /> },
];

export function HostDetail({ ip, onBack }: Props) {
  const { data, loading, error, refetch } = useApi<HostOut>(() => api.getHost(ip), [ip]);

  if (loading) {
    return (
      <div className="p-3 space-y-2">
        <button onClick={onBack} className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-2">
          <ArrowLeft size={14} /> Back
        </button>
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-8 animate-pulse rounded bg-gray-800/50" />
        ))}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-3">
        <button onClick={onBack} className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-2">
          <ArrowLeft size={14} /> Back
        </button>
        <p className="text-sm text-red-400">{error || 'Host not found'}</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="border-b border-gray-800 px-3 py-2">
        <button onClick={onBack} className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-2">
          <ArrowLeft size={14} /> Back to list
        </button>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 rounded-full shrink-0" style={{ backgroundColor: getRoleColor(data.role) }} />
          <div>
            <p className="text-sm font-mono text-gray-100 font-semibold">{data.ip}</p>
            {data.hostname && <p className="text-xs text-gray-500">{data.hostname}</p>}
          </div>
        </div>
        <div className="flex flex-wrap gap-2 mt-2 text-xs">
          <span className="rounded bg-gray-800 px-1.5 py-0.5" style={{ color: getRoleColor(data.role) }}>
            {data.role}
          </span>
          {data.is_new && (
            <span className="rounded bg-green-900/30 px-1.5 py-0.5 text-green-400 font-semibold">NEW</span>
          )}
          {data.is_stale && (
            <span className="rounded bg-gray-700 px-1.5 py-0.5 text-gray-500 font-semibold">GONE</span>
          )}
          {!data.is_new && !data.is_stale && data.has_changes && (
            <span className="rounded bg-yellow-900/30 px-1.5 py-0.5 text-yellow-400 font-semibold">CHANGED</span>
          )}
          {data.os_name && (
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400">{data.os_name}</span>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Services */}
        <ServicesList services={data.services} vulns={data.vulnerabilities} hostIp={ip} onUpdated={refetch} />

        <VulnsList vulns={data.vulnerabilities} hostIp={ip} onUpdated={refetch} />
      </div>
    </div>
  );
}

/** Group vulns by cve_id, merge ports, show deduped list. */
function VulnsList({ vulns, hostIp, onUpdated }: {
  vulns: HostOut['vulnerabilities'];
  hostIp: string;
  onUpdated: () => void;
}) {
  const grouped = useMemo(() => {
    const map = new Map<string, { vuln: VulnOut; ports: number[] }>();
    for (const v of vulns) {
      const existing = map.get(v.cve_id);
      if (existing) {
        if (v.port != null && !existing.ports.includes(v.port)) {
          existing.ports.push(v.port);
        }
        // Keep highest CVSS, exploit info, worst status
        if (v.cvss > existing.vuln.cvss) existing.vuln = { ...existing.vuln, cvss: v.cvss };
        if (v.has_exploit && !existing.vuln.has_exploit) existing.vuln = { ...existing.vuln, has_exploit: true };
        if (v.exploit_url && !existing.vuln.exploit_url) existing.vuln = { ...existing.vuln, exploit_url: v.exploit_url };
        if (v.exploit_module && !existing.vuln.exploit_module) existing.vuln = { ...existing.vuln, exploit_module: v.exploit_module };
      } else {
        map.set(v.cve_id, { vuln: v, ports: v.port != null ? [v.port] : [] });
      }
    }
    // Sort ports within each group
    for (const entry of map.values()) {
      entry.ports.sort((a, b) => a - b);
    }
    return [...map.values()];
  }, [vulns]);

  return (
    <div>
      <div className="flex items-center gap-1.5 px-3 py-2">
        <Bug size={13} className="text-red-400" />
        <span className="text-xs font-medium text-gray-400">
          Vulnerabilities ({grouped.filter(g => g.vuln.checked_status !== 'false_positive').length}{grouped.length !== vulns.length ? ` on ${vulns.filter(v => v.checked_status !== 'false_positive').length} ports` : ''})
        </span>
      </div>
      <div className="px-3 pb-2 space-y-1">
        {grouped.map(({ vuln, ports }) => (
          <VulnRow key={vuln.cve_id} vuln={vuln} ports={ports} hostIp={hostIp} onUpdated={onUpdated} />
        ))}
        {grouped.length === 0 && (
          <p className="text-xs text-gray-600">No vulnerabilities</p>
        )}
      </div>
    </div>
  );
}

function VulnRow({ vuln, ports, hostIp, onUpdated }: { vuln: VulnOut; ports: number[]; hostIp: string; onUpdated: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);
  const currentStatus = vuln.checked_status || null;

  const handleStatusChange = useCallback(async (status: VulnStatus) => {
    setUpdating(true);
    try {
      const newStatus = status === currentStatus ? null : status;
      // Apply status to all affected ports
      await Promise.all(
        ports.length > 0
          ? ports.map(p => api.updateVulnStatus(hostIp, vuln.cve_id, newStatus, p))
          : [api.updateVulnStatus(hostIp, vuln.cve_id, newStatus, vuln.port)]
      );
      onUpdated();
    } catch (e) {
      console.error('Failed to update vuln status:', e);
    } finally {
      setUpdating(false);
    }
  }, [hostIp, vuln.cve_id, vuln.port, ports, currentStatus, onUpdated]);

  return (
    <div className={`rounded bg-gray-800/30 ${currentStatus === 'false_positive' ? 'opacity-50' : ''}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-2 py-1.5 text-left flex items-center gap-2"
      >
        {ports.length > 0 && (
          <span className="font-mono text-xs text-gray-500 shrink-0" title={ports.join(', ')}>
            :{ports[0]}{ports.length > 1 && <span className="text-gray-600">+{ports.length - 1}</span>}
          </span>
        )}
        {vuln.cvss > 0 && (
          <span
            className="font-mono text-xs shrink-0"
            style={{ color: getCvssColor(vuln.cvss) }}
          >
            {vuln.cvss.toFixed(1)}
          </span>
        )}
        <span className="text-xs text-gray-300 truncate flex-1 flex items-center gap-1">
          <span
            className="truncate hover:text-white cursor-pointer"
            title="Click to copy"
            onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(vuln.cve_id); }}
          >
            {vuln.cve_id}
          </span>
          {vuln.cve_id.startsWith('CVE-') && (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="shrink-0 text-gray-600 hover:text-blue-400"
              title="Open in NVD"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink size={10} />
            </a>
          )}
        </span>
        <span
          className="text-xs shrink-0"
          style={{ color: getConfidenceColor(vuln.confidence) }}
        >
          {vuln.confidence}
        </span>
        {vuln.has_exploit && (
          <span className="text-xs shrink-0 rounded px-1 py-0 bg-red-900/30 text-red-400 font-semibold">
            EXPLOIT
          </span>
        )}
        {vuln.source && (
          <span className={`text-xs shrink-0 rounded px-1 py-0 ${
            vuln.source === 'ai' ? 'bg-purple-900/30 text-purple-400' :
            vuln.source === 'exploit_db' ? 'bg-amber-900/30 text-amber-400' :
            vuln.source === 'nvd' ? 'bg-cyan-900/30 text-cyan-400' :
            'bg-gray-700 text-gray-400'
          }`}>
            {vuln.source === 'ai' ? 'AI' : vuln.source === 'exploit_db' ? 'DB' : vuln.source === 'nvd' ? 'NVD' : vuln.source}
          </span>
        )}
        {currentStatus && (
          <span className="text-xs shrink-0" style={{
            color: currentStatus === 'exploited' ? '#22c55e' :
                   currentStatus === 'mitigated' ? '#3b82f6' : '#6b7280'
          }}>
            {currentStatus === 'exploited' && <Check size={12} />}
            {currentStatus === 'false_positive' && <X size={12} />}
            {currentStatus === 'mitigated' && <Shield size={12} />}
          </span>
        )}
        {expanded ? <ChevronUp size={12} className="text-gray-600" /> : <ChevronDown size={12} className="text-gray-600" />}
      </button>

      {expanded && (
        <div className="px-2 pb-2 space-y-1.5">
          {ports.length > 1 && (
            <p className="text-xs text-gray-500 font-mono">Ports: {ports.join(', ')}</p>
          )}
          {vuln.description && (
            <p className="text-xs text-gray-500">{vuln.description}</p>
          )}
          <div className="flex items-center gap-1 flex-wrap text-xs text-gray-600">
            {vuln.enables_pivot === true && (
              <span className="rounded bg-red-900/30 px-1 py-0.5 text-red-400">RCE</span>
            )}
            {vuln.enables_pivot === false && (
              <span className="rounded bg-gray-700 px-1 py-0.5 text-gray-400">relay/misc</span>
            )}
            {vuln.exploit_module && (
              <span className="rounded bg-gray-700 px-1 py-0.5 text-gray-400 font-mono truncate max-w-full" title={vuln.exploit_module}>
                {vuln.exploit_module}
              </span>
            )}
          </div>
          {vuln.exploit_url && (
            <a
              href={vuln.exploit_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-blue-400 hover:text-blue-300 truncate block"
              title={vuln.exploit_url}
            >
              {vuln.exploit_url}
            </a>
          )}
          {/* Status buttons */}
          <div className="flex items-center gap-1 pt-1 border-t border-gray-700/50">
            <span className="text-xs text-gray-600 mr-1">Status:</span>
            {STATUS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                disabled={updating}
                onClick={(e) => { e.stopPropagation(); handleStatusChange(opt.value); }}
                className={`flex items-center gap-0.5 rounded px-1.5 py-0.5 text-xs transition-colors ${
                  currentStatus === opt.value
                    ? 'ring-1 ring-offset-1 ring-offset-gray-900'
                    : 'opacity-60 hover:opacity-100'
                }`}
                style={{
                  color: opt.color,
                  backgroundColor: opt.color + '18',
                  ...(currentStatus === opt.value ? { ringColor: opt.color } : {}),
                }}
              >
                {opt.icon}
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ServicesList({ services, vulns, hostIp, onUpdated }: {
  services: HostOut['services'];
  vulns: HostOut['vulnerabilities'];
  hostIp: string;
  onUpdated: () => void;
}) {
  // Build port → max CVSS map from vulns
  const portCvssMap = useMemo(() => {
    const map = new Map<number, number>();
    for (const v of vulns) {
      if (v.port != null) {
        const current = map.get(v.port) || 0;
        const cvss = v.cvss || 0;
        map.set(v.port, Math.max(current, cvss));
      }
    }
    return map;
  }, [vulns]);

  // Build port → vuln count
  const portVulnCount = useMemo(() => {
    const map = new Map<number, number>();
    for (const v of vulns) {
      if (v.port != null) {
        map.set(v.port, (map.get(v.port) || 0) + 1);
      }
    }
    return map;
  }, [vulns]);

  const handleBruteToggle = useCallback(async (port: number, current: boolean) => {
    try {
      await api.updateServiceBruteforceable(hostIp, port, !current);
      onUpdated();
    } catch (e) {
      console.error('Failed to toggle bruteforceable:', e);
    }
  }, [hostIp, onUpdated]);

  const [credsPort, setCredsPort] = useState<number | null>(null);
  const [creds, setCreds] = useState<Array<{ username: string; password: string }>>([]);
  const [credsLoading, setCredsLoading] = useState(false);

  const handleShowCreds = useCallback(async (port: number) => {
    if (credsPort === port) { setCredsPort(null); return; }
    setCredsPort(port);
    setCredsLoading(true);
    try {
      const res = await api.getDefaultCreds(hostIp, port);
      setCreds(res.creds);
    } catch { setCreds([]); }
    finally { setCredsLoading(false); }
  }, [hostIp, credsPort]);

  const [notesPort, setNotesPort] = useState<number | null>(null);
  const [notesText, setNotesText] = useState('');
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleToggleNotes = useCallback((port: number, currentNotes: string | null) => {
    if (notesPort === port) { setNotesPort(null); return; }
    setNotesPort(port);
    setNotesText(currentNotes || '');
  }, [notesPort]);

  const handleNotesChange = useCallback((value: string) => {
    setNotesText(value);
    // Auto-save after 500ms of inactivity
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(async () => {
      try {
        await api.updateServiceNotes(hostIp, notesPort!, value || null);
      } catch (e) { console.error('Failed to save notes:', e); }
    }, 500);
  }, [hostIp, notesPort]);

  return (
    <div className="border-b border-gray-800">
      <div className="flex items-center gap-1.5 px-3 py-2">
        <Server size={13} className="text-blue-400" />
        <span className="text-xs font-medium text-gray-400">Services ({services.length})</span>
      </div>
      <div className="px-3 pb-2 space-y-0.5">
        {services.map((s) => {
          const maxCvss = portCvssMap.get(s.port) || 0;
          const vCount = portVulnCount.get(s.port) || 0;
          const portColor = maxCvss > 0 ? getCvssColor(maxCvss) : '#60a5fa';

          return (
            <div key={`${s.port}/${s.protocol}`}>
              <div className={`flex items-center gap-2 text-xs ${s.is_stale ? 'opacity-40' : ''}`}>
                <span
                  className={`font-mono w-14 text-right shrink-0 ${s.is_stale ? 'line-through' : ''}`}
                  style={{ color: portColor }}
                >
                  {s.port}/{s.protocol}
                </span>
                <span className={`text-gray-400 truncate ${s.is_stale ? 'line-through' : ''}`}>
                  {s.name}{s.product && ` — ${s.product}`}{s.version && ` ${s.version}`}
                </span>
                {s.is_new && (
                  <span className="shrink-0 rounded px-1 py-0 bg-green-900/30 text-green-400 font-semibold">NEW</span>
                )}
                {s.is_stale && (
                  <span className="shrink-0 rounded px-1 py-0 bg-gray-700 text-gray-500">GONE</span>
                )}
                {vCount > 0 && (
                  <span
                    className="shrink-0 rounded px-1 py-0 text-xs"
                    style={{ color: portColor, backgroundColor: portColor + '18' }}
                    title={`${vCount} vulnerability${vCount !== 1 ? 'ies' : ''} on this port`}
                  >
                    <Bug size={9} className="inline mr-0.5 -mt-px" />{vCount}
                  </span>
                )}
                <button
                  onClick={() => handleBruteToggle(s.port, s.bruteforceable)}
                  className={`shrink-0 rounded px-1 py-0 text-xs transition-colors ${
                    s.bruteforceable
                      ? 'bg-orange-900/30 text-orange-400 font-semibold'
                      : 'bg-gray-800 text-gray-600 hover:text-gray-400'
                  }`}
                  title={s.bruteforceable ? 'Bruteforceable — click to unmark' : 'Mark as bruteforceable'}
                >
                  BRUTE
                </button>
                {s.bruteforceable && (
                  <button
                    onClick={() => handleShowCreds(s.port)}
                    className={`shrink-0 rounded px-1 py-0 text-xs transition-colors ${
                      credsPort === s.port
                        ? 'bg-yellow-900/30 text-yellow-400 font-semibold'
                        : 'bg-gray-800 text-gray-600 hover:text-yellow-400'
                    }`}
                    title="Show default credentials"
                  >
                    <Key size={9} className="inline mr-0.5 -mt-px" />CREDS
                  </button>
                )}
                <button
                  onClick={() => handleToggleNotes(s.port, s.notes)}
                  className={`shrink-0 rounded px-1 py-0 text-xs transition-colors ${
                    notesPort === s.port
                      ? 'bg-blue-900/30 text-blue-400 font-semibold'
                      : s.notes
                        ? 'bg-blue-900/20 text-blue-400/70'
                        : 'bg-gray-800 text-gray-600 hover:text-blue-400'
                  }`}
                  title={s.notes ? 'Edit notes' : 'Add notes'}
                >
                  <MessageSquare size={9} className="inline mr-0.5 -mt-px" />{s.notes ? 'NOTE' : '+'}
                </button>
              </div>
              {credsPort === s.port && (
                <div className="ml-16 mb-1 rounded bg-yellow-950/20 border border-yellow-800/30 px-2 py-1">
                  {credsLoading ? (
                    <span className="text-xs text-gray-500">Loading...</span>
                  ) : creds.length > 0 ? (
                    <div className="space-y-0.5">
                      <span className="text-xs text-yellow-400/70 font-medium">Default credentials:</span>
                      {creds.map((c, i) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 text-xs font-mono cursor-pointer hover:bg-yellow-900/20 rounded px-1"
                          onClick={() => {
                            const text = c.password ? `${c.username}:${c.password}` : c.username || '(empty)';
                            navigator.clipboard.writeText(text);
                          }}
                          title="Click to copy"
                        >
                          <span className="text-yellow-300">{c.username || '(empty)'}</span>
                          <span className="text-gray-600">:</span>
                          <span className="text-yellow-200">{c.password || '(empty)'}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-gray-500">No known default credentials</span>
                  )}
                </div>
              )}
              {notesPort === s.port && (
                <div className="ml-16 mb-1">
                  <textarea
                    value={notesText}
                    onChange={(e) => handleNotesChange(e.target.value)}
                    placeholder="Add notes... (auto-saves)"
                    className="w-full rounded bg-gray-800 border border-blue-900/30 px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 outline-none focus:ring-1 focus:ring-blue-500 resize-y min-h-[60px]"
                    rows={3}
                  />
                </div>
              )}
            </div>
          );
        })}
        {services.length === 0 && (
          <p className="text-xs text-gray-600">No services</p>
        )}
      </div>
    </div>
  );
}
