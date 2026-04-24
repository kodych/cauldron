import { useState, useCallback, useRef, useEffect } from 'react';
import { Upload, FileText, Play, Check, AlertCircle, Brain, Trash2, Download } from 'lucide-react';
import { api } from '../api/client';
import type { ImportResponse, AnalyzeResponse, AnalysisJobStatus } from '../types';

// Map backend phase codes ("nvd", "ai", "classify"...) to pentester-readable
// labels. Shown in the progress bar during analysis — raw "nvd" and "ai"
// mean nothing to someone who didn't read our API docs.
const PHASE_LABELS: Record<string, string> = {
  queued:    'Queued',
  classify:  'Classifying hosts',
  exploits:  'Matching exploits',
  scripts:   'Verifying NSE scripts',
  brute:     'Detecting brute-forceable',
  nvd:       'Enriching CVEs (NVD)',
  epss:      'Fetching EPSS scores',
  paths:     'Computing attack paths',
  ai:        'AI triage',
  done:      'Complete',
};

interface Props {
  onImported?: () => void;
  onAnalyzed?: () => void;
  onReset?: () => void;
}

export function ImportPanel({ onImported, onAnalyzed, onReset }: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState('');
  const [useNvd, setUseNvd] = useState(false);
  const [useAi, setUseAi] = useState(false);
  const [importing, setImporting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [importResult, setImportResult] = useState<ImportResponse | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [analyzeElapsed, setAnalyzeElapsed] = useState(0);
  const [analyzeProgress, setAnalyzeProgress] = useState<AnalysisJobStatus | null>(null);
  const [includeNotes, setIncludeNotes] = useState(false);

  const handleFile = useCallback((f: File) => {
    if (!f.name.endsWith('.xml') && !f.name.endsWith('.json')) {
      setError('Supported formats: Nmap XML, Masscan XML/JSON');
      return;
    }
    setFile(f);
    setError(null);
    setImportResult(null);
    if (!source) {
      setSource(f.name.replace(/\.xml$/i, ''));
    }
  }, [source]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  }, [handleFile]);

  const handleImport = useCallback(async () => {
    if (!file) return;
    setImporting(true);
    setError(null);
    try {
      const result = await api.importScan(file, source || undefined);
      setImportResult(result);
      onImported?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  }, [file, source, onImported]);

  // Elapsed time ticker during analysis. The `finally` block in
  // `handleAnalyze` already clears it on completion/error, but if the
  // component unmounts mid-run (tab switch won't, but a parent remount
  // can) the interval would keep firing into detached state. Mount-wide
  // cleanup below kills it unconditionally on unmount.
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, []);

  const handleAnalyze = useCallback(async () => {
    setAnalyzing(true);
    setError(null);
    setAnalyzeResult(null);
    setAnalyzeProgress(null);
    const start = Date.now();
    setAnalyzeElapsed(0);
    timerRef.current = setInterval(() => setAnalyzeElapsed(Date.now() - start), 1000);
    try {
      // Use background-job endpoint to survive 10+ minute NVD enrichment on
      // large networks without hitting browser fetch timeout.
      const result = await api.runAnalysisWithProgress(
        { nvd: useNvd, ai: useAi },
        (status) => setAnalyzeProgress(status),
      );
      setAnalyzeResult(result);
      onAnalyzed?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed');
    } finally {
      setAnalyzing(false);
      if (timerRef.current) { clearInterval(timerRef.current); timerRef.current = null; }
    }
  }, [useNvd, useAi, onAnalyzed]);

  const resetForm = useCallback(() => {
    setFile(null);
    setSource('');
    setImportResult(null);
    setError(null);
    // The <input type="file"> DOM element keeps its internal value even
    // when React state clears. Without this, selecting the same file
    // again after "Import another" produces no onChange event (browser
    // sees an unchanged value), so the drop zone looks frozen.
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  const handleResetDatabase = useCallback(async () => {
    setResetting(true);
    setError(null);
    try {
      await api.resetDatabase();
      resetForm();
      setAnalyzeResult(null);
      onReset?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Reset failed');
    } finally {
      setResetting(false);
      setConfirmReset(false);
    }
  }, [resetForm, onReset]);

  return (
    <div className="p-3 space-y-3">
      {/* === IMPORT SECTION === */}
      <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Import Scan</p>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-4 text-center cursor-pointer transition-colors ${
          dragOver
            ? 'border-steel-400 bg-steel-950/20'
            : file
              ? 'border-green-600/50 bg-green-950/10'
              : 'border-gray-700 hover:border-gray-600'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".xml,.json"
          className="hidden"
          onChange={(e) => {
            if (e.target.files?.[0]) handleFile(e.target.files[0]);
            // Clear so selecting the same file a second time still fires
            // onChange. The native input suppresses the event when value
            // hasn't changed — emptying it here makes every selection a
            // "new" one from the browser's perspective.
            e.target.value = '';
          }}
        />
        {file ? (
          <div className="flex items-center justify-center gap-2">
            <FileText size={16} className="text-green-400" />
            <span className="text-xs text-green-400">{file.name}</span>
            <span className="text-xs text-gray-600">({(file.size / 1024).toFixed(0)} KB)</span>
          </div>
        ) : (
          <div>
            <Upload size={20} className="mx-auto text-gray-600 mb-1" />
            <p className="text-xs text-gray-500">Drop scan file here or click to browse</p>
          </div>
        )}
      </div>

      {/* Scanner source */}
      {file && !importResult && (
        <div>
          <label className="text-xs text-gray-400 block mb-1">
            Scanner IP <span className="text-gray-600">(where was the scan run from?)</span>
          </label>
          <input
            type="text"
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder="e.g., 10.0.0.7 or kali-external"
            className="w-full rounded bg-gray-800 px-2 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600 outline-none focus:ring-1 focus:ring-steel-500"
          />
          <p className="mt-1 text-xs text-gray-600">
            Identifies the scan position in the network. Multiple scans from different positions build multi-perspective attack paths.
          </p>
        </div>
      )}

      {/* Import button */}
      {file && !importResult && (
        <button
          onClick={handleImport}
          disabled={importing}
          className="w-full flex items-center justify-center gap-1.5 rounded bg-steel-600 py-2 text-xs text-white hover:bg-steel-500 disabled:opacity-50"
        >
          {importing ? (
            <>
              <div className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
              Importing...
            </>
          ) : (
            <>
              <Upload size={13} />
              Import Scan
            </>
          )}
        </button>
      )}

      {/* Import result */}
      {importResult && (
        <div className="rounded bg-green-950/20 border border-green-800/30 p-2 space-y-1">
          <div className="flex items-center gap-1.5">
            <Check size={13} className="text-green-400" />
            <span className="text-xs font-medium text-green-400">Import successful</span>
          </div>
          <div className="grid grid-cols-2 gap-1 text-xs">
            <span className="text-gray-500">Hosts:</span>
            <span className="text-gray-300">{importResult.hosts_imported}</span>
            <span className="text-gray-500">Services:</span>
            <span className="text-gray-300">{importResult.services_imported}</span>
            <span className="text-gray-500">Skipped:</span>
            <span className="text-gray-300">{importResult.hosts_skipped}</span>
          </div>
        </div>
      )}

      {/* Import another */}
      {(importResult || file) && (
        <button
          onClick={resetForm}
          className="w-full rounded bg-gray-800 py-1.5 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200"
        >
          Import another scan
        </button>
      )}

      {/* === ANALYZE SECTION === */}
      <div className="border-t border-gray-800 pt-3">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Analyze</p>

        {/* Enrichment toggles */}
        <div className="space-y-1.5 mb-2">
          <label className="flex items-center gap-2 px-1 cursor-pointer">
            <input
              type="checkbox"
              checked={useNvd}
              onChange={(e) => setUseNvd(e.target.checked)}
              className="rounded border-gray-600 bg-gray-800 text-cyan-500"
            />
            <span className="text-xs text-cyan-400">NVD</span>
            <span className="text-xs text-gray-500">CVE enrichment (may take minutes)</span>
          </label>
          <label className="flex items-center gap-2 px-1 cursor-pointer">
            <input
              type="checkbox"
              checked={useAi}
              onChange={(e) => setUseAi(e.target.checked)}
              className="rounded border-gray-600 bg-gray-800 text-purple-500"
            />
            <Brain size={13} className="text-purple-400" />
            <span className="text-xs text-gray-400">AI analysis (Claude API)</span>
          </label>
        </div>

        {!analyzeResult ? (
          <div>
            <button
              onClick={handleAnalyze}
              disabled={analyzing}
              className="w-full flex items-center justify-center gap-1.5 rounded bg-orange-600 py-2 text-xs text-white hover:bg-orange-500 disabled:opacity-50"
            >
              {analyzing ? (
                <>
                  <div className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
                  Analyzing{useNvd || useAi ? ` (${[useNvd && 'NVD', useAi && 'AI'].filter(Boolean).join(' + ')})` : ''}...
                  {analyzeElapsed > 0 && (
                    <span className="font-mono ml-1">
                      {Math.floor(analyzeElapsed / 60000)}:{String(Math.floor((analyzeElapsed % 60000) / 1000)).padStart(2, '0')}
                    </span>
                  )}
                </>
              ) : (
                <>
                  <Play size={13} />
                  Run Analysis
                </>
              )}
            </button>
            {analyzing && analyzeProgress && (
              <div className="mt-2 space-y-1">
                <div className="flex items-center gap-2 text-xs">
                  {/* Live cauldron frame-by-frame animation — literal
                      "boil" metaphor while the backend is brewing. WebP
                      preserves alpha so it composites cleanly on the
                      panel background; image-rendering:pixelated keeps
                      the pixel art crisp at this small display size. */}
                  <img
                    src="/brand/cauldron-anim-32.webp"
                    alt=""
                    width={26}
                    height={26}
                    className="shrink-0"
                    style={{ imageRendering: 'pixelated' }}
                  />
                  <span className="text-orange-400 font-semibold shrink-0">
                    {PHASE_LABELS[analyzeProgress.phase] ?? analyzeProgress.phase}
                  </span>
                  <span className="text-gray-400 flex-1 truncate">
                    {analyzeProgress.message}
                  </span>
                  {analyzeProgress.total > 0 && (
                    <span className="font-mono text-gray-500 shrink-0">
                      {analyzeProgress.current}/{analyzeProgress.total}
                      {analyzeProgress.phase === 'nvd' && ' services'}
                    </span>
                  )}
                </div>
                {analyzeProgress.total > 0 && (
                  <div className="h-1 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-orange-500 transition-all duration-300"
                      style={{ width: `${Math.min(100, (analyzeProgress.current / analyzeProgress.total) * 100)}%` }}
                    />
                  </div>
                )}
              </div>
            )}
            {!analyzing && (
              <p className="text-xs text-gray-600 px-1 mt-1">
                Classify hosts, match exploits, find attack paths{useNvd ? ', NVD CVEs' : ''}{useAi ? ', AI analysis' : ''}
              </p>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            <div className="rounded bg-orange-950/20 border border-orange-800/30 p-2 space-y-2">
              <div className="flex items-center gap-1.5">
                <Check size={13} className="text-orange-400" />
                <span className="text-xs font-medium text-orange-400">Analysis complete</span>
              </div>
              <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-xs">
                {analyzeResult.classification?.classified != null && (
                  <>
                    <span className="text-gray-500">Classified:</span>
                    <span className="text-gray-300">{String(analyzeResult.classification.classified)} hosts</span>
                  </>
                )}
                {analyzeResult.exploits?.matched != null && (
                  <>
                    <span className="text-gray-500">Exploits found:</span>
                    <span className="text-gray-300">{String(analyzeResult.exploits.matched)}</span>
                  </>
                )}
                {analyzeResult.path_summary?.vulnerable_hosts != null && (
                  <>
                    <span className="text-gray-500">Vulnerable hosts:</span>
                    <span className="text-gray-300">{String(analyzeResult.path_summary.vulnerable_hosts)}</span>
                  </>
                )}
                {(analyzeResult.ai_vulns_dismissed ?? 0) > 0 && (
                  <>
                    <span className="text-gray-500">AI dismissed:</span>
                    <span className="text-red-400">-{analyzeResult.ai_vulns_dismissed} vulns</span>
                  </>
                )}
                {(analyzeResult.ai_vulns_kept ?? 0) > 0 && (
                  <>
                    <span className="text-gray-500">AI kept:</span>
                    <span className="text-green-400">{analyzeResult.ai_vulns_kept} gold</span>
                  </>
                )}
                {(analyzeResult.ai_targets_set ?? 0) > 0 && (
                  <>
                    <span className="text-gray-500">AI targets:</span>
                    <span className="text-red-400">+{analyzeResult.ai_targets_set} targets</span>
                  </>
                )}
                {(analyzeResult.ai_cves_found ?? 0) > 0 && (
                  <>
                    <span className="text-gray-500">AI CVEs:</span>
                    <span className="text-purple-400">+{analyzeResult.ai_cves_found} new</span>
                  </>
                )}
              </div>
            </div>
            {/* Keeps the results visible but gives a way back to the
                "Run Analysis" button. Without this the only ways to
                re-trigger analysis are a full page reload or resetting
                the database. */}
            <button
              onClick={() => setAnalyzeResult(null)}
              className="w-full rounded bg-gray-800 py-1.5 text-xs text-gray-400 hover:bg-gray-700 hover:text-gray-200"
            >
              Run another analysis
            </button>
          </div>
        )}
      </div>

      {/* === ERROR === */}
      {error && (
        <div className="flex items-start gap-1.5 rounded bg-red-950/20 border border-red-800/30 p-2">
          <AlertCircle size={13} className="text-red-400 shrink-0 mt-0.5" />
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      {/* === EXPORT REPORT === */}
      <div className="border-t border-gray-800 pt-3">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">Export Report</p>
        <label className="flex items-center gap-2 px-1 mb-2 cursor-pointer">
          <input
            type="checkbox"
            checked={includeNotes}
            onChange={(e) => setIncludeNotes(e.target.checked)}
            className="rounded border-gray-600 bg-gray-800 text-blue-500"
          />
          <span className="text-xs text-gray-400">Include notes</span>
        </label>
        <div className="flex gap-2">
          {(['md', 'json', 'html'] as const).map((fmt) => (
            <a
              key={fmt}
              href={`/api/v1/report?fmt=${fmt}${includeNotes ? '&notes=true' : ''}`}
              download={`cauldron_report.${fmt === 'md' ? 'md' : fmt}`}
              className="flex-1 flex items-center justify-center gap-1 rounded bg-gray-800 py-1.5 text-xs text-gray-400 hover:bg-steel-950/30 hover:text-steel-400 transition-colors"
            >
              <Download size={11} />
              {fmt.toUpperCase()}
            </a>
          ))}
        </div>
      </div>

      {/* === CLEAR DATABASE === */}
      <div className="border-t border-gray-800 pt-3">
        {!confirmReset ? (
          <button
            onClick={() => setConfirmReset(true)}
            className="w-full flex items-center justify-center gap-1.5 rounded bg-gray-800 py-1.5 text-xs text-gray-500 hover:bg-red-950/30 hover:text-red-400 transition-colors"
          >
            <Trash2 size={13} />
            Clear Database
          </button>
        ) : (
          <div className="space-y-2">
            <p className="text-xs text-red-400 text-center">
              This will delete all hosts, services, and vulnerabilities.
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setConfirmReset(false)}
                className="flex-1 rounded bg-gray-800 py-1.5 text-xs text-gray-400 hover:bg-gray-700"
              >
                Cancel
              </button>
              <button
                onClick={handleResetDatabase}
                disabled={resetting}
                className="flex-1 flex items-center justify-center gap-1 rounded bg-red-700 py-1.5 text-xs text-white hover:bg-red-600 disabled:opacity-50"
              >
                {resetting ? (
                  <div className="h-3 w-3 animate-spin rounded-full border border-white border-t-transparent" />
                ) : (
                  <Trash2 size={12} />
                )}
                Confirm
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
