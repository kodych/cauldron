import { useState, useCallback, useRef } from 'react';
import { Upload, FileText, Play, Check, AlertCircle, Brain, Trash2 } from 'lucide-react';
import { api } from '../api/client';
import type { ImportResponse, AnalyzeResponse } from '../types';

interface Props {
  onImported?: () => void;
}

export function ImportPanel({ onImported }: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState('');
  const [useAi, setUseAi] = useState(false);
  const [importing, setImporting] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [importResult, setImportResult] = useState<ImportResponse | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetting, setResetting] = useState(false);

  const handleFile = useCallback((f: File) => {
    if (!f.name.endsWith('.xml')) {
      setError('Only Nmap XML files (.xml) are supported');
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

  const handleAnalyze = useCallback(async () => {
    setAnalyzing(true);
    setError(null);
    setAnalyzeResult(null);
    try {
      const result = await api.runAnalysis(useAi);
      setAnalyzeResult(result);
      setTimeout(() => window.location.reload(), 1500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  }, [useAi]);

  const resetForm = useCallback(() => {
    setFile(null);
    setSource('');
    setImportResult(null);
    setError(null);
  }, []);

  const handleResetDatabase = useCallback(async () => {
    setResetting(true);
    setError(null);
    try {
      await api.resetDatabase();
      resetForm();
      setAnalyzeResult(null);
      setTimeout(() => window.location.reload(), 500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Reset failed');
    } finally {
      setResetting(false);
      setConfirmReset(false);
    }
  }, [resetForm]);

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
            ? 'border-indigo-400 bg-indigo-950/20'
            : file
              ? 'border-green-600/50 bg-green-950/10'
              : 'border-gray-700 hover:border-gray-600'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".xml"
          className="hidden"
          onChange={(e) => {
            if (e.target.files?.[0]) handleFile(e.target.files[0]);
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
            <p className="text-xs text-gray-500">Drop Nmap XML here or click to browse</p>
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
            className="w-full rounded bg-gray-800 px-2 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600 outline-none focus:ring-1 focus:ring-indigo-500"
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
          className="w-full flex items-center justify-center gap-1.5 rounded bg-indigo-600 py-2 text-xs text-white hover:bg-indigo-500 disabled:opacity-50"
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

        {/* AI toggle */}
        <label className="flex items-center gap-2 px-1 cursor-pointer mb-2">
          <input
            type="checkbox"
            checked={useAi}
            onChange={(e) => setUseAi(e.target.checked)}
            className="rounded border-gray-600 bg-gray-800 text-purple-500"
          />
          <Brain size={13} className="text-purple-400" />
          <span className="text-xs text-gray-400">Include AI analysis (Claude API)</span>
        </label>

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
                  Analyzing{useAi ? ' (with AI)' : ''}...
                </>
              ) : (
                <>
                  <Play size={13} />
                  Run Analysis
                </>
              )}
            </button>
            <p className="text-xs text-gray-600 px-1 mt-1">
              Classify hosts, match exploits, enrich CVEs, build topology{useAi ? ', AI attack chains' : ''}
            </p>
          </div>
        ) : (
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
            </div>
            <p className="text-xs text-gray-500">Reloading page...</p>
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
