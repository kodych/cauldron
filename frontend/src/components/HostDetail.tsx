import { useState, useCallback, useMemo } from 'react';
import { ArrowLeft, Shield, Server, Bug, ChevronDown, ChevronUp, Check, X } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getRoleColor, getConfidenceColor, getCvssColor } from '../utils/colors';
import { formatCvss } from '../utils/format';
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
          {data.os_name && (
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400">{data.os_name}</span>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Services */}
        <ServicesList services={data.services} vulns={data.vulnerabilities} />

        <div>
          <div className="flex items-center gap-1.5 px-3 py-2">
            <Bug size={13} className="text-red-400" />
            <span className="text-xs font-medium text-gray-400">Vulnerabilities ({data.vulnerabilities.length})</span>
          </div>
          <div className="px-3 pb-2 space-y-1">
            {data.vulnerabilities.map((v) => (
              <VulnRow key={v.cve_id} vuln={v} hostIp={ip} onUpdated={refetch} />
            ))}
            {data.vulnerabilities.length === 0 && (
              <p className="text-xs text-gray-600">No vulnerabilities</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function VulnRow({ vuln, hostIp, onUpdated }: { vuln: VulnOut; hostIp: string; onUpdated: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);
  const currentStatus = vuln.checked_status || null;

  const handleStatusChange = useCallback(async (status: VulnStatus) => {
    setUpdating(true);
    try {
      const newStatus = status === currentStatus ? null : status;
      await api.updateVulnStatus(hostIp, vuln.cve_id, newStatus);
      onUpdated();
    } catch (e) {
      console.error('Failed to update vuln status:', e);
    } finally {
      setUpdating(false);
    }
  }, [hostIp, vuln.cve_id, currentStatus, onUpdated]);

  return (
    <div className={`rounded bg-gray-800/30 ${currentStatus === 'false_positive' ? 'opacity-50' : ''}`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-2 py-1.5 text-left flex items-center gap-2"
      >
        {vuln.cvss > 0 && (
          <span
            className="font-mono text-xs shrink-0"
            style={{ color: getCvssColor(vuln.cvss) }}
          >
            {vuln.cvss.toFixed(1)}
          </span>
        )}
        <span className="text-xs text-gray-300 truncate flex-1">{vuln.cve_id}</span>
        <span
          className="text-xs shrink-0"
          style={{ color: getConfidenceColor(vuln.confidence) }}
        >
          {vuln.confidence}
        </span>
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
          {vuln.description && (
            <p className="text-xs text-gray-500">{vuln.description}</p>
          )}
          <div className="flex items-center gap-1 text-xs text-gray-600">
            {vuln.enables_pivot === true && (
              <span className="rounded bg-red-900/30 px-1 py-0.5 text-red-400">RCE</span>
            )}
            {vuln.enables_pivot === false && (
              <span className="rounded bg-gray-700 px-1 py-0.5 text-gray-400">relay/misc</span>
            )}
          </div>
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

function ServicesList({ services, vulns }: { services: HostOut['services']; vulns: HostOut['vulnerabilities'] }) {
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
            <div key={`${s.port}/${s.protocol}`} className="flex items-center gap-2 text-xs">
              <span
                className="font-mono w-14 text-right shrink-0"
                style={{ color: portColor }}
              >
                {s.port}/{s.protocol}
              </span>
              <span className="text-gray-400 truncate">
                {s.name}{s.product && ` — ${s.product}`}{s.version && ` ${s.version}`}
              </span>
              {vCount > 0 && (
                <span
                  className="shrink-0 rounded px-1 py-0 text-xs font-mono"
                  style={{ color: portColor, backgroundColor: portColor + '18' }}
                >
                  {vCount}
                </span>
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
