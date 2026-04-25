import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { ArrowLeft, Shield, Server, Bug, ChevronDown, ChevronUp, Check, X, Key, MessageSquare, StickyNote, Clipboard, Target, Unlock, AlertCircle, Flame } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import { getRoleColor, getCvssColor, cvssSeverity, osFamilyTone, osFamilyLabel } from '../utils/colors';
import type { HostOut, VulnOut, VulnStatus } from '../types';
import { Badge } from './Badge';
import { ExploitCommands } from './ExploitCommands';

interface Props {
  ip: string;
  onBack: () => void;
  onDataChanged?: () => void;
}

const STATUS_OPTIONS: { value: VulnStatus; label: string; color: string; icon: React.ReactNode }[] = [
  { value: 'exploited', label: 'Exploited', color: '#22c55e', icon: <Check size={13} strokeWidth={2.5} /> },
  { value: 'false_positive', label: 'False Positive', color: '#9ca3af', icon: <X size={13} strokeWidth={2.5} /> },
  { value: 'mitigated', label: 'Mitigated', color: '#3b82f6', icon: <Shield size={12} strokeWidth={2.5} /> },
];

export function HostDetail({ ip, onBack, onDataChanged }: Props) {
  const { data, loading, error, refetch } = useApi<HostOut>(() => api.getHost(ip), [ip]);
  const [hostNotesOpen, setHostNotesOpen] = useState(false);
  const [hostNotesText, setHostNotesText] = useState('');
  // Auto-save state machine: 'saving' while debounce/request pending,
  // 'saved' for ~1.5s after success (so the operator sees a confirmation
  // and doesn't wonder whether their note landed), 'error' on API failure
  // so silent network glitches stop eating notes. 'idle' hides the hint.
  const [hostNotesStatus, setHostNotesStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [ipCopied, setIpCopied] = useState(false);
  const [toggleBusy, setToggleBusy] = useState(false);
  const hostNotesSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hostNotesClearRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset notes panel state when switching to a different host
  useEffect(() => {
    setHostNotesOpen(false);
    setHostNotesText('');
    setHostNotesStatus('idle');
  }, [ip]);

  // Esc closes the detail panel. This matches the modal-dismissal
  // convention users expect from Gmail/Slack/GitHub — auto-save has
  // already persisted typed notes via its 500ms debounce so closing
  // doesn't lose work, and it makes "glance at next host" a single key
  // away instead of a mouse round-trip to the Back button. Only active
  // while HostDetail is mounted; the listener unwires on unmount.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onBack();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onBack]);

  const handleToggleHostNotes = useCallback(() => {
    if (!hostNotesOpen && data) {
      setHostNotesText(data.notes || '');
      setHostNotesStatus('idle');
    }
    setHostNotesOpen((v) => !v);
  }, [hostNotesOpen, data]);

  const handleHostNotesChange = useCallback((value: string) => {
    setHostNotesText(value);
    setHostNotesStatus('saving');
    if (hostNotesSaveRef.current) clearTimeout(hostNotesSaveRef.current);
    if (hostNotesClearRef.current) clearTimeout(hostNotesClearRef.current);
    hostNotesSaveRef.current = setTimeout(async () => {
      try {
        await api.updateHostNotes(ip, value || null);
        setHostNotesStatus('saved');
        hostNotesClearRef.current = setTimeout(() => setHostNotesStatus('idle'), 1500);
        // Refetch the host so ``data.notes`` reflects what we just
        // saved. Without this, the next time the operator closes and
        // reopens the notes panel, ``handleToggleHostNotes`` resets
        // the textarea from the stale prop and the just-typed text
        // appears to vanish (it's actually safely stored in the DB —
        // a refresh confirms it).
        refetch();
      } catch (e) {
        console.error('Failed to save host notes:', e);
        setHostNotesStatus('error');
      }
    }, 500);
  }, [ip]);

  const handleCopyIp = useCallback(async () => {
    await navigator.clipboard.writeText(ip);
    setIpCopied(true);
    setTimeout(() => setIpCopied(false), 1500);
  }, [ip]);

  const handleToggleOwned = useCallback(async () => {
    if (!data) return;
    setToggleBusy(true);
    try {
      await api.setHostOwned(ip, !data.owned);
      refetch();
      onDataChanged?.();
    } finally {
      setToggleBusy(false);
    }
  }, [ip, data, refetch, onDataChanged]);

  const handleToggleTarget = useCallback(async () => {
    if (!data) return;
    setToggleBusy(true);
    try {
      await api.setHostTarget(ip, !data.target);
      refetch();
      onDataChanged?.();
    } finally {
      setToggleBusy(false);
    }
  }, [ip, data, refetch, onDataChanged]);

  // Skeleton only on the INITIAL load when there's nothing to show.
  // Once we have ``data`` cached, a background refetch (triggered by
  // notes save, owned/target toggle, status change, etc.) keeps the
  // current UI on screen instead of unmounting it. Without this guard
  // every refetch flashed the skeleton, which unmounted ServicesList
  // and lost its local state — so typing a single character into a
  // service-notes textarea (which auto-saves and refetches after 500ms)
  // collapsed the notes panel right under the operator's cursor.
  if (loading && !data) {
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
          <ArrowLeft size={14} /> Back
        </button>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 rounded-full shrink-0" style={{ backgroundColor: getRoleColor(data.role) }} />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              <p className="text-sm font-mono text-gray-100 font-semibold truncate">{data.ip}</p>
              <button
                onClick={handleCopyIp}
                title="Copy IP"
                className="rounded p-0.5 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
              >
                {ipCopied ? <Check size={12} className="text-green-400" /> : <Clipboard size={12} />}
              </button>
            </div>
            {data.hostname && <p className="text-xs text-gray-500 truncate">{data.hostname}</p>}
          </div>
        </div>
        <div className="flex flex-wrap gap-2 mt-2 text-xs">
          <span className="rounded bg-gray-800 px-1.5 py-0.5" style={{ color: getRoleColor(data.role) }}>
            {data.role}
          </span>
          {data.is_new && <Badge tone="green">NEW</Badge>}
          {data.is_stale && <Badge tone="gray">GONE</Badge>}
          {!data.is_new && !data.is_stale && data.has_changes && (
            <Badge tone="yellow">CHANGED</Badge>
          )}
          {/* OS family badge — coloured by platform when nmap classified
              with high enough confidence (>= 85% from osclass, or any
              service-ostype hint which has no scoring but is binary).
              Tooltip carries the full ``os_name`` plus accuracy so the
              operator can sanity-check the call. ``os_name`` raw text
              is the fallback when family is null or low-confidence. */}
          {(() => {
            const fam = data.os_family;
            const acc = data.os_accuracy;
            const showBadge = fam && (acc == null || acc >= 85);
            const detail = data.os_name
              ? `${data.os_name}${acc ? ` (nmap ${acc}% confidence)` : ''}`
              : undefined;
            if (showBadge) {
              const tone = osFamilyTone(fam) ?? 'gray';
              const label = osFamilyLabel(fam);
              const subtitle = data.os_gen && !label.includes(data.os_gen)
                ? ` ${data.os_gen}` : '';
              return (
                <Badge tone={tone} title={detail}>
                  {label}{subtitle}
                </Badge>
              );
            }
            if (data.os_name) {
              return (
                <span
                  className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400"
                  title={acc != null ? `nmap accuracy ${acc}%` : 'OS not confidently classified'}
                >
                  {data.os_name}
                </span>
              );
            }
            return null;
          })()}
        </div>
        {/* Visual divider between identity (IP / role / OS / scan-state)
            and engagement-actions (Owned / Target / Notes). They were
            stacked as if equal weight before; the operator's eye now
            knows which line is "what is this host" and which is "what
            do I want to do with it". */}
        <div className="my-2 border-t border-gray-800/70" />
        {/* Owned / Target toggles */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={handleToggleOwned}
            disabled={toggleBusy}
            title={data.owned ? 'Unmark as Owned' : 'Mark as Owned — we have access'}
            className={`flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors disabled:opacity-50 ${
              data.owned
                ? 'bg-green-900/40 text-green-400 font-semibold'
                : 'bg-gray-800 text-gray-500 hover:text-gray-300'
            }`}
          >
            <Unlock size={11} />
            {data.owned ? 'Owned' : 'Mark Owned'}
          </button>
          <button
            onClick={handleToggleTarget}
            disabled={toggleBusy}
            title={data.target ? 'Unmark as Target' : 'Mark as Target — high-value'}
            className={`flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors disabled:opacity-50 ${
              data.target
                ? 'bg-red-900/40 text-red-400 font-semibold'
                : 'bg-gray-800 text-gray-500 hover:text-gray-300'
            }`}
          >
            <Target size={11} />
            {data.target ? 'Target' : 'Mark Target'}
          </button>
        </div>
        {/* Host Notes — same row-rhythm as the Owned/Target toggles
            since they're the same kind of engagement-state action. */}
        <div className="mt-1.5">
          <button
            onClick={handleToggleHostNotes}
            className={`flex items-center gap-1 rounded px-1.5 py-0.5 text-xs transition-colors ${
              hostNotesOpen
                ? 'bg-blue-900/30 text-blue-400 font-semibold'
                : data.notes
                  ? 'bg-blue-900/20 text-blue-400/70'
                  : 'bg-gray-800 text-gray-600 hover:text-blue-400'
            }`}
          >
            <StickyNote size={11} />
            {data.notes ? 'Host Notes' : 'Add Host Notes'}
          </button>
          {hostNotesOpen && (
            <>
              <textarea
                value={hostNotesText}
                onChange={(e) => handleHostNotesChange(e.target.value)}
                placeholder="Add host-level notes... (auto-saves)"
                className="mt-1 w-full rounded bg-gray-800 border border-blue-900/30 px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 outline-none focus:ring-1 focus:ring-blue-500 resize-y min-h-[60px]"
                rows={3}
              />
              {hostNotesStatus === 'saving' && (
                <p className="text-xs text-gray-500 mt-0.5 italic">Saving…</p>
              )}
              {hostNotesStatus === 'saved' && (
                <p className="text-xs text-green-500 mt-0.5 flex items-center gap-1">
                  <Check size={11} /> Saved
                </p>
              )}
              {hostNotesStatus === 'error' && (
                <p className="text-xs text-red-400 mt-0.5 flex items-center gap-1">
                  <AlertCircle size={11} /> Not saved — edit to retry
                </p>
              )}
            </>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Services */}
        <ServicesList services={data.services} vulns={data.vulnerabilities} hostIp={ip} onUpdated={refetch} />

        <VulnsList vulns={data.vulnerabilities} hostIp={ip} onUpdated={() => { refetch(); onDataChanged?.(); }} />
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

  // Header counts: explicit "active vs dismissed" so the visible row
  // count never disagrees with the header. Earlier we showed only
  // ``activeGroups.length`` and the operator saw e.g. "(1)" with 4 rows
  // visible (3 of them FP-marked) — cognitive dissonance.
  const headerLabel = (() => {
    const total = grouped.length;
    if (total === 0) return 'Vulnerabilities';
    const active = grouped.filter(g => g.vuln.checked_status !== 'false_positive').length;
    const dismissed = total - active;
    const portCount = new Set(
      vulns.map(v => v.port).filter((p): p is number => p != null),
    ).size;
    const portSuffix = portCount > 1 ? ` · ${portCount} ports` : '';
    if (dismissed === 0) return `Vulnerabilities · ${active}${portSuffix}`;
    if (active === 0) return `Vulnerabilities · ${dismissed} dismissed${portSuffix}`;
    return `Vulnerabilities · ${active} active, ${dismissed} dismissed${portSuffix}`;
  })();

  return (
    <div>
      <div className="flex items-center gap-1.5 px-3 py-2">
        <Bug size={13} className="text-red-400" />
        <span className="text-xs font-medium text-gray-400">{headerLabel}</span>
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
  // Unified FP modal: click "False Positive" status button → modal asks
  // for reason + scope (this host vs all hosts). "All hosts" path
  // requires a second confirmation step before firing the bulk endpoint.
  const [fpOpen, setFpOpen] = useState(false);
  const [fpReason, setFpReason] = useState('');
  const [fpConfirmAll, setFpConfirmAll] = useState(false);
  const [fpBusy, setFpBusy] = useState(false);
  const [fpError, setFpError] = useState<string | null>(null);
  const [cveCopied, setCveCopied] = useState(false);
  const currentStatus = vuln.checked_status || null;

  const handleCopyCve = useCallback(async () => {
    await navigator.clipboard.writeText(vuln.cve_id);
    setCveCopied(true);
    setTimeout(() => setCveCopied(false), 1500);
  }, [vuln.cve_id]);

  const closeFpModal = useCallback(() => {
    if (fpBusy) return;
    setFpOpen(false);
    setFpReason('');
    setFpConfirmAll(false);
    setFpError(null);
  }, [fpBusy]);

  const handleStatusChange = useCallback(async (status: VulnStatus) => {
    // FP is a special case — needs a reason and a scope. Open the
    // modal instead of firing immediately, except when toggling OFF
    // an already-FP'd edge (un-FP needs no annotation).
    if (status === 'false_positive' && currentStatus !== 'false_positive') {
      setFpOpen(true);
      return;
    }
    setUpdating(true);
    try {
      const newStatus = status === currentStatus ? null : status;
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

  const applyFpThisHost = useCallback(async () => {
    const reason = fpReason.trim();
    if (!reason) {
      setFpError('Reason is required');
      return;
    }
    setFpBusy(true);
    setFpError(null);
    try {
      await Promise.all(
        ports.length > 0
          ? ports.map(p => api.updateVulnStatus(hostIp, vuln.cve_id, 'false_positive', p, reason))
          : [api.updateVulnStatus(hostIp, vuln.cve_id, 'false_positive', vuln.port, reason)]
      );
      onUpdated();
      closeFpModal();
    } catch (e) {
      console.error('FP apply failed:', e);
      setFpError('Server error. Try again.');
    } finally {
      setFpBusy(false);
    }
  }, [hostIp, vuln.cve_id, vuln.port, ports, fpReason, onUpdated, closeFpModal]);

  const applyFpAllHosts = useCallback(async () => {
    const reason = fpReason.trim();
    if (!reason) {
      setFpError('Reason is required');
      return;
    }
    setFpBusy(true);
    setFpError(null);
    try {
      const result = await api.bulkUpdateVulnStatus(vuln.cve_id, reason);
      console.info(`Bulk FP applied to ${result.affected} edges for ${vuln.cve_id}`);
      onUpdated();
      closeFpModal();
    } catch (e) {
      console.error('Bulk FP failed:', e);
      setFpError('Server error. Try again.');
    } finally {
      setFpBusy(false);
    }
  }, [vuln.cve_id, fpReason, onUpdated, closeFpModal]);

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
            title={`CVSS ${vuln.cvss.toFixed(1)} — ${cvssSeverity(vuln.cvss)} severity`}
          >
            {vuln.cvss.toFixed(1)}
          </span>
        )}
        <span className="text-xs text-gray-300 truncate flex-1 flex items-center gap-1">
          {vuln.cve_id.startsWith('CVE-') ? (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="truncate hover:text-blue-400 hover:underline"
              title="Open in NVD"
              onClick={(e) => e.stopPropagation()}
            >
              {vuln.cve_id}
            </a>
          ) : (
            <span className="truncate">{vuln.cve_id}</span>
          )}
          <button
            onClick={(e) => { e.stopPropagation(); handleCopyCve(); }}
            title={cveCopied ? 'Copied!' : 'Copy CVE ID'}
            className="shrink-0 rounded p-0.5 text-gray-500 hover:bg-gray-800 hover:text-gray-200"
          >
            {cveCopied
              ? <Check size={11} className="text-green-400" />
              : <Clipboard size={11} />}
          </button>
          {/* Subtle "?" marker when this CVE's matched service had no
              concrete version. The service row already carries the same
              hint after the product name; the per-vuln marker preserves
              context when the operator scrolls deep into the vulns
              section and the service line is off-screen. */}
          {vuln.version_unconfirmed && (
            <span
              className="shrink-0 text-yellow-500/70 cursor-help"
              title="Service version was unknown when this CVE was linked. The CVE applies to *some* versions of this product but we can't confirm it covers the build actually running here — verify before acting on this finding."
              onClick={(e) => e.stopPropagation()}
            >
              ?
            </span>
          )}
        </span>
        {/* Primary signals — loud colors, only the most important
            information is allowed to compete for attention here. */}
        {vuln.in_cisa_kev && (
          <span className="shrink-0">
            <Badge
              tone="orange"
              strong
              title={vuln.cisa_kev_added ? `In CISA KEV since ${vuln.cisa_kev_added.slice(0, 10)} — actively exploited in the wild` : 'CISA Known Exploited Vulnerability — actively exploited in the wild'}
            >
              <Flame size={10} /> KEV
            </Badge>
          </span>
        )}
        {vuln.has_exploit && !vuln.in_cisa_kev && (
          <span className="shrink-0">
            <Badge tone="red">EXPLOIT</Badge>
          </span>
        )}
        {vuln.epss != null && vuln.epss >= 0.1 && (
          <span className="shrink-0">
            <Badge
              tone={vuln.epss >= 0.9 ? 'red' : vuln.epss >= 0.5 ? 'orange' : 'yellow'}
              strong={vuln.epss >= 0.9}
              title={`EPSS ${(vuln.epss * 100).toFixed(1)}% — FIRST.org probability of exploitation in the next 30 days`}
            >
              EPSS {Math.round(vuln.epss * 100)}%
            </Badge>
          </span>
        )}
        {/* Secondary metadata — same muted style for confidence /
            attack surface / source, so they read as "reference info"
            rather than competing with the primary signals above. The
            ``check`` confidence is the default and carries no signal,
            so we render confidence only when it differs. */}
        {vuln.confidence && vuln.confidence !== 'check' && (
          <span className="shrink-0">
            <Badge tone="gray" title={`AI/script confidence: ${vuln.confidence}`}>
              {vuln.confidence}
            </Badge>
          </span>
        )}
        {/* version_unconfirmed is shown at the SERVICE level (see
            ServicesList) to avoid repeating the same warning on every
            CVE row. It's still on VulnOut for aggregate views (Vulns
            tab, report) where service context isn't visible. */}
        {vuln.source && (
          <span className="shrink-0">
            <Badge tone="gray" title={`Source: ${vuln.source.toUpperCase()}`}>
              {vuln.source === 'ai' ? 'AI' : vuln.source === 'exploit_db' ? 'DB' : vuln.source === 'nvd' ? 'NVD' : vuln.source}
            </Badge>
          </span>
        )}
        {/* Inline status quick-picker — primary triage action, must be
            visibly affordant as a button group, not a row of three
            naked icons that newcomers can't recognize. Implemented as a
            segmented control: bordered container, divided cells, active
            cell tinted in its own colour, inactive cells with a clear
            hover state. Tooltip carries the full action name. */}
        <span
          className="flex items-stretch shrink-0 ml-2 rounded border border-gray-700 overflow-hidden divide-x divide-gray-700"
          onClick={(e) => e.stopPropagation()}
        >
          {STATUS_OPTIONS.map((opt) => {
            const isActive = currentStatus === opt.value;
            return (
              <button
                key={opt.value}
                disabled={updating}
                onClick={() => handleStatusChange(opt.value)}
                title={isActive ? `Clear ${opt.label}` : `Mark as ${opt.label}`}
                aria-label={isActive ? `Clear ${opt.label}` : `Mark as ${opt.label}`}
                className={`flex items-center px-1.5 py-0.5 transition-colors ${
                  isActive
                    ? 'font-semibold'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                }`}
                style={isActive
                  ? { color: opt.color, backgroundColor: opt.color + '22' }
                  : undefined}
              >
                {opt.icon}
              </button>
            );
          })}
        </span>
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
          {vuln.ai_fp_reason && (
            <p className="text-xs text-yellow-600 italic">AI: {vuln.ai_fp_reason}</p>
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
          {/* Exploit Commands */}
          <ExploitCommands hostIp={hostIp} port={ports[0] || vuln.port || 0} vulnId={vuln.cve_id} />
          {/* Status pickers live in the collapsed row now (compact,
              always visible). The expanded view doesn't duplicate them
              — the inline icons reach the same handler / modal. */}
        </div>
      )}
      {fpOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
          onClick={(e) => { e.stopPropagation(); closeFpModal(); }}
        >
          <div
            className="w-full max-w-md rounded border border-gray-700 bg-gray-900 p-4 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-gray-200">
              <X size={14} className="text-gray-400" />
              Mark <span className="font-mono">{vuln.cve_id}</span> as False Positive
            </h3>
            <label className="block text-xs text-gray-500 mb-1">
              Reason (required):
            </label>
            <textarea
              value={fpReason}
              onChange={(e) => { setFpReason(e.target.value); setFpError(null); setFpConfirmAll(false); }}
              placeholder="e.g. Terrapin requires MITM, out of scope for this engagement"
              rows={2}
              disabled={fpBusy}
              className="mb-3 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-gray-200 focus:border-gray-500 focus:outline-none"
              autoFocus
            />
            {fpError && (
              <p className="mb-2 text-xs text-red-400">{fpError}</p>
            )}
            {fpConfirmAll ? (
              <div className="rounded border border-yellow-700/50 bg-yellow-950/30 p-2 mb-2">
                <p className="mb-2 flex items-start gap-1.5 text-xs text-yellow-200">
                  <AlertCircle size={12} className="mt-0.5 shrink-0" />
                  <span>
                    This will mark <span className="font-mono">{vuln.cve_id}</span> as false
                    positive on <strong>every host where it's currently active</strong>.
                    Already-decided edges (exploited / mitigated) are preserved.
                  </span>
                </p>
                <div className="flex justify-end gap-2">
                  <button
                    disabled={fpBusy}
                    onClick={() => setFpConfirmAll(false)}
                    className="rounded bg-gray-800 px-3 py-1 text-xs text-gray-300 hover:bg-gray-700"
                  >
                    Back
                  </button>
                  <button
                    disabled={fpBusy}
                    onClick={applyFpAllHosts}
                    className="rounded bg-red-900/60 px-3 py-1 text-xs font-semibold text-red-200 hover:bg-red-900"
                  >
                    {fpBusy ? 'Applying...' : 'Yes — apply to all hosts'}
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex justify-end gap-2">
                <button
                  disabled={fpBusy}
                  onClick={closeFpModal}
                  className="rounded bg-gray-800 px-3 py-1 text-xs text-gray-300 hover:bg-gray-700"
                >
                  Cancel
                </button>
                <button
                  disabled={fpBusy || !fpReason.trim()}
                  onClick={applyFpThisHost}
                  className="rounded bg-gray-700 px-3 py-1 text-xs text-gray-200 hover:bg-gray-600 disabled:opacity-50"
                >
                  {fpBusy ? 'Applying...' : 'Apply to this host'}
                </button>
                <button
                  disabled={fpBusy || !fpReason.trim()}
                  onClick={() => { setFpError(null); setFpConfirmAll(true); }}
                  className="rounded bg-red-900/40 px-3 py-1 text-xs font-semibold text-red-200 hover:bg-red-900/60 disabled:opacity-50"
                >
                  Apply to all hosts
                </button>
              </div>
            )}
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

  // Sort services by port number ascending — the backend returns them in
  // whatever order Cypher matched, which on real scans surfaces as
  // 5432, 3389, 445, 139, 135, 22 (random-looking from the operator's
  // perspective). Same protocol comes before different protocol on
  // identical port number.
  const sortedServices = useMemo(() => {
    return [...services].sort((a, b) => {
      if (a.port !== b.port) return a.port - b.port;
      return (a.protocol || '').localeCompare(b.protocol || '');
    });
  }, [services]);

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
  // Track fetch failure separately from empty-creds so a backend hiccup
  // looks different from a service that genuinely has no default-creds
  // entries in the DB (most services with no well-known defaults).
  const [credsError, setCredsError] = useState(false);

  const loadCreds = useCallback(async (port: number) => {
    setCredsLoading(true);
    setCredsError(false);
    try {
      const res = await api.getDefaultCreds(hostIp, port);
      setCreds(res.creds);
    } catch (e) {
      console.error('Failed to load default creds:', e);
      setCreds([]);
      setCredsError(true);
    } finally {
      setCredsLoading(false);
    }
  }, [hostIp]);

  const handleShowCreds = useCallback(async (port: number) => {
    // Toggle: clicking the same port again closes the panel.
    if (credsPort === port) { setCredsPort(null); return; }
    setCredsPort(port);
    await loadCreds(port);
  }, [credsPort, loadCreds]);

  const [notesPort, setNotesPort] = useState<number | null>(null);
  const [notesText, setNotesText] = useState('');
  const [notesStatus, setNotesStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const savedClearRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleToggleNotes = useCallback((port: number, currentNotes: string | null) => {
    if (notesPort === port) { setNotesPort(null); return; }
    setNotesPort(port);
    setNotesText(currentNotes || '');
    setNotesStatus('idle');
  }, [notesPort]);

  const handleNotesChange = useCallback((value: string) => {
    setNotesText(value);
    setNotesStatus('saving');
    // Auto-save after 500ms of inactivity
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    if (savedClearRef.current) clearTimeout(savedClearRef.current);
    saveTimerRef.current = setTimeout(async () => {
      try {
        await api.updateServiceNotes(hostIp, notesPort!, value || null);
        setNotesStatus('saved');
        savedClearRef.current = setTimeout(() => setNotesStatus('idle'), 1500);
        // Refetch the host so ``s.notes`` on the matching service
        // reflects what we just saved. Without this, the next time
        // the operator closes and reopens the notes panel for the
        // same port, ``handleToggleNotes`` resets the textarea from
        // the stale prop and the saved text appears to vanish.
        onUpdated();
      } catch (e) {
        console.error('Failed to save notes:', e);
        setNotesStatus('error');
      }
    }, 500);
  }, [hostIp, notesPort, onUpdated]);

  return (
    <div className="border-b border-gray-800">
      <div className="flex items-center gap-1.5 px-3 py-2">
        <Server size={13} className="text-blue-400" />
        <span className="text-xs font-medium text-gray-400">Services ({services.length})</span>
      </div>
      <div className="px-3 pb-2 space-y-0.5">
        {sortedServices.map((s) => {
          const maxCvss = portCvssMap.get(s.port) || 0;
          const vCount = portVulnCount.get(s.port) || 0;
          const portColor = maxCvss > 0 ? getCvssColor(maxCvss) : '#60a5fa';

          return (
            <div key={`${s.port}/${s.protocol}`}>
              <div className={`flex items-center gap-2 text-xs ${s.is_stale ? 'opacity-40' : ''}`}>
                <span
                  className={`font-mono tabular-nums w-[4.5rem] shrink-0 ${s.is_stale ? 'line-through' : ''}`}
                  style={{ color: portColor }}
                >
                  {s.port}/{s.protocol}
                </span>
                <span className={`text-gray-400 truncate ${s.is_stale ? 'line-through' : ''}`}>
                  {s.name}{s.product && ` — ${s.product}`}{s.version && ` ${s.version}`}
                  {/* Subtle "?" after the product name when version
                      is unknown. nmap couldn't pin a specific version,
                      so CVE-linkage relies on a wildcard NVD match —
                      the linked CVEs may or may not apply to the
                      actual build. Hover-tooltip explains; no badge
                      box, just a dim character. */}
                  {s.product && (!s.version || s.version === '*') && (
                    <span
                      className="ml-0.5 text-yellow-500/70 cursor-help"
                      title="Version not detected by nmap. CVEs were attached via wildcard CPE match — they apply to *some* versions of this product, but we can't confirm whether they cover the actual build running here. Verify with deeper version detection or the vendor admin panel."
                    >
                      ?
                    </span>
                  )}
                </span>
                {s.is_new && <span className="shrink-0"><Badge tone="green">NEW</Badge></span>}
                {s.is_stale && <span className="shrink-0"><Badge tone="gray">GONE</Badge></span>}
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
                  ) : credsError ? (
                    <div className="flex items-center gap-2 text-xs text-red-400">
                      <AlertCircle size={11} />
                      <span>Failed to load credentials.</span>
                      <button
                        onClick={() => loadCreds(s.port)}
                        className="rounded bg-red-900/30 px-1.5 py-0.5 text-red-300 hover:bg-red-900/50"
                      >
                        Retry
                      </button>
                    </div>
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
                  {notesStatus === 'saving' && (
                    <p className="text-xs text-gray-500 mt-0.5 italic">Saving…</p>
                  )}
                  {notesStatus === 'saved' && (
                    <p className="text-xs text-green-500 mt-0.5 flex items-center gap-1">
                      <Check size={11} /> Saved
                    </p>
                  )}
                  {notesStatus === 'error' && (
                    <p className="text-xs text-red-400 mt-0.5 flex items-center gap-1">
                      <AlertCircle size={11} /> Not saved — edit to retry
                    </p>
                  )}
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


