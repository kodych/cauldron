import { useEffect } from 'react';
import { ArrowLeft, Crosshair, Clock } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import type { ScanSourceOut } from '../types';

interface Props {
  name: string;
  onBack: () => void;
}

// Compact detail view for a ``scan_source`` node clicked on the canvas.
//
// We keep this deliberately minimal: just the data the operator can act
// on or audit with. Scan sources that doubled as pivot hosts (e.g.
// ``10.0.2.10`` for web01) merge into the host node and use ``HostDetail``
// — this component only fires for the standalone case (external scanner
// boxes that never got scanned themselves).
//
// Three fields cover the "what was this scan" question:
//   - scan_args   : the nmap command line, copyable verbatim
//   - first_seen  : when this position first appeared in the graph
//   - last_seen   : when the operator last imported from here (==
//                   first_seen if only one import has happened)
export function ScanSourceDetail({ name, onBack }: Props) {
  const { data, loading, error } = useApi<ScanSourceOut>(
    () => api.getScanSource(name),
    [name],
  );

  // Esc closes — same affordance as HostDetail.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onBack();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onBack]);

  if (loading && !data) {
    return (
      <div className="p-3 space-y-2">
        <button
          onClick={onBack}
          className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-2"
        >
          <ArrowLeft size={14} /> Back
        </button>
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-8 animate-pulse rounded bg-gray-800/50" />
        ))}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-3">
        <button
          onClick={onBack}
          className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-2"
        >
          <ArrowLeft size={14} /> Back
        </button>
        <p className="text-sm text-red-400">{error || 'Scan source not found'}</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="border-b border-gray-800 px-3 py-2">
        <button
          onClick={onBack}
          className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 mb-2"
        >
          <ArrowLeft size={14} /> Back
        </button>
        <div className="flex items-center gap-2">
          <Crosshair size={14} className="text-emerald-400 shrink-0" />
          <p className="font-mono text-sm text-gray-100 font-semibold truncate">{data.name}</p>
        </div>
        <p className="mt-1 text-xs text-gray-500">Scan position</p>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        <section>
          <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-1">Scan args</h3>
          {data.scan_args ? (
            <pre className="rounded bg-gray-900 border border-gray-800 px-2 py-1.5 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
              {data.scan_args}
            </pre>
          ) : (
            <p className="text-xs text-gray-600 italic">Not recorded</p>
          )}
        </section>

        <section>
          <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-1">Activity</h3>
          <div className="space-y-1 text-xs">
            <div className="flex items-center gap-2 text-gray-300">
              <Clock size={11} className="text-gray-500 shrink-0" />
              <span className="text-gray-500 w-20 shrink-0">First seen</span>
              <span className="font-mono">{formatTs(data.first_seen)}</span>
            </div>
            <div className="flex items-center gap-2 text-gray-300">
              <Clock size={11} className="text-gray-500 shrink-0" />
              <span className="text-gray-500 w-20 shrink-0">Last seen</span>
              <span className="font-mono">{formatTs(data.last_seen)}</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

// Render an ISO timestamp as a compact local-time string. Falls back to
// the raw value on parse failure so we never silently swallow a bad
// timestamp from the backend.
function formatTs(ts: string | null): string {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}
