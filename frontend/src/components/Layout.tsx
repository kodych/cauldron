import { useCallback, useEffect, useState } from 'react';
import {
  Network, BarChart3, Shield, Crosshair, ChevronLeft, ChevronRight,
  Target, Upload,
} from 'lucide-react';
import { StatsPanel } from './StatsPanel';
import { HostList } from './HostList';
import { AttackPaths } from './AttackPaths';
import { CollectPanel } from './CollectPanel';
import { ImportPanel } from './ImportPanel';
import { HostDetail } from './HostDetail';
import { GraphCanvas } from './GraphCanvas';
import { Legend } from './Legend';

type Tab = 'stats' | 'hosts' | 'paths' | 'collect' | 'import';

// --- Sidebar width persistence ---
//
// The sidebar is drag-resizable from its right edge. The chosen width is
// remembered in localStorage so each operator's preference (laptop 1366,
// dock 1920, ultrawide) persists across sessions. Clamped to a sane range
// so the graph canvas always retains breathing room and the sidebar can
// always show host detail content without horizontal scrollbars.
const SIDEBAR_MIN_WIDTH = 320;
const SIDEBAR_MAX_WIDTH = 720;
const SIDEBAR_DEFAULT_WIDTH = 400;
const SIDEBAR_COLLAPSED_WIDTH = 48;
const SIDEBAR_WIDTH_KEY = 'cauldron:sidebar-width';
const SIDEBAR_GRAPH_RESERVE = 200;  // never let sidebar push graph below this

function clampSidebarWidth(value: number): number {
  if (typeof window !== 'undefined') {
    const max = Math.min(SIDEBAR_MAX_WIDTH, window.innerWidth - SIDEBAR_GRAPH_RESERVE);
    return Math.max(SIDEBAR_MIN_WIDTH, Math.min(max, value));
  }
  return Math.max(SIDEBAR_MIN_WIDTH, Math.min(SIDEBAR_MAX_WIDTH, value));
}

function readStoredSidebarWidth(): number {
  try {
    const raw = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    if (!raw) return SIDEBAR_DEFAULT_WIDTH;
    const w = parseInt(raw, 10);
    if (Number.isNaN(w)) return SIDEBAR_DEFAULT_WIDTH;
    return clampSidebarWidth(w);
  } catch {
    return SIDEBAR_DEFAULT_WIDTH;
  }
}

export function Layout() {
  const [activeTab, setActiveTab] = useState<Tab>('stats');
  const [collapsed, setCollapsed] = useState(false);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [showHostDetail, setShowHostDetail] = useState(false);
  const [graphKey, setGraphKey] = useState(0);
  const [dataVersion, setDataVersion] = useState(0);
  const [selectedPathIps, setSelectedPathIps] = useState<string[] | null>(null);
  const [sidebarWidth, setSidebarWidth] = useState<number>(readStoredSidebarWidth);
  const [resizing, setResizing] = useState(false);

  // Persist width preference only after the drag ends, not on every mouse
  // move — otherwise localStorage takes a write per mousemove tick.
  useEffect(() => {
    if (resizing) return;
    try {
      localStorage.setItem(SIDEBAR_WIDTH_KEY, String(sidebarWidth));
    } catch {
      // localStorage unavailable (private mode, quota) — silent fallback.
    }
  }, [resizing, sidebarWidth]);

  // Drag-to-resize: install global mouse listeners while the user is dragging
  // the handle. Using window-level listeners (rather than the handle element)
  // means the cursor can leave the thin handle bar without losing the drag.
  useEffect(() => {
    if (!resizing) return;
    const onMove = (e: MouseEvent) => {
      setSidebarWidth(clampSidebarWidth(e.clientX));
    };
    const onUp = () => setResizing(false);
    document.body.style.cursor = 'ew-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [resizing]);

  // Window resize: re-clamp so an ultrawide preference doesn't swallow the
  // graph after the operator docks/undocks to a smaller display.
  useEffect(() => {
    const onResize = () => setSidebarWidth((w) => clampSidebarWidth(w));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setResizing(true);
  }, []);

  const handleResizeReset = useCallback(() => {
    setSidebarWidth(SIDEBAR_DEFAULT_WIDTH);
  }, []);

  const handleSelectHost = useCallback((ip: string | null) => {
    setSelectedHost(ip);
    if (ip) {
      setShowHostDetail(true);
    }
  }, []);

  const handleBackFromDetail = useCallback(() => {
    setShowHostDetail(false);
  }, []);

  const bumpDataVersion = useCallback(() => setDataVersion((v) => v + 1), []);

  const handleImported = useCallback(() => {
    // Force graph refresh by changing key, and propagate data version bump
    setGraphKey((k) => k + 1);
    setDataVersion((v) => v + 1);
  }, []);

  const handleClearPath = useCallback(() => setSelectedPathIps(null), []);

  const handleReset = useCallback(() => {
    // Kill graph state (empty DB) and refresh all panels
    setSelectedHost(null);
    setShowHostDetail(false);
    setSelectedPathIps(null);
    setGraphKey((k) => k + 1);
    setDataVersion((v) => v + 1);
  }, []);

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'stats', label: 'Dashboard', icon: <BarChart3 size={15} /> },
    { id: 'hosts', label: 'Hosts', icon: <Network size={15} /> },
    { id: 'paths', label: 'Paths', icon: <Crosshair size={15} /> },
    { id: 'collect', label: 'Collect', icon: <Target size={15} /> },
    { id: 'import', label: 'Import', icon: <Upload size={15} /> },
  ];

  return (
    <div className="flex h-screen w-screen bg-gray-950">
      {/* Sidebar — drag-resizable from right edge, collapse via header chevron.
          Width is inline-styled so dragging is frame-perfect; transition is
          only enabled when toggling collapse so the bar doesn't feel laggy
          during an active drag. */}
      <div
        className={`flex flex-col border-r border-gray-800 bg-gray-900 relative shrink-0 ${
          resizing ? '' : 'transition-[width] duration-150'
        }`}
        style={{ width: collapsed ? SIDEBAR_COLLAPSED_WIDTH : sidebarWidth }}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 px-3 py-3">
          {!collapsed && (
            <div className="flex items-center gap-2">
              <Shield size={20} className="text-indigo-400" />
              <span className="text-sm font-semibold text-gray-100">Cauldron</span>
            </div>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
          >
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>

        {/* Tabs */}
        {!collapsed && (
          <div className="flex border-b border-gray-800">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => { setActiveTab(tab.id); setShowHostDetail(false); }}
                className={`flex flex-1 items-center justify-center gap-1 py-2.5 text-xs font-medium transition-colors ${
                  activeTab === tab.id && !showHostDetail
                    ? 'border-b-2 border-indigo-400 text-indigo-400'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>
        )}

        {/* Panel content */}
        {!collapsed && (
          <div className="flex-1 overflow-y-auto">
            {/* Host detail overlays tab content but tabs stay mounted so filters/scroll survive */}
            {showHostDetail && selectedHost && (
              <HostDetail ip={selectedHost} onBack={handleBackFromDetail} onDataChanged={bumpDataVersion} />
            )}
            <div className={showHostDetail ? 'hidden' : ''}>
              <div className={activeTab === 'stats' ? '' : 'hidden'}>
                <StatsPanel refreshKey={dataVersion} />
              </div>
              <div className={activeTab === 'hosts' ? '' : 'hidden'}>
                <HostList onSelectHost={handleSelectHost} selectedHost={selectedHost} refreshKey={dataVersion} />
              </div>
              <div className={activeTab === 'paths' ? '' : 'hidden'}>
                <AttackPaths onSelectPath={setSelectedPathIps} onSelectHost={handleSelectHost} refreshKey={dataVersion} />
              </div>
              <div className={activeTab === 'collect' ? '' : 'hidden'}>
                <CollectPanel refreshKey={dataVersion} />
              </div>
              <div className={activeTab === 'import' ? '' : 'hidden'}>
                <ImportPanel onImported={handleImported} onAnalyzed={handleImported} onReset={handleReset} />
              </div>
            </div>
          </div>
        )}

        {/* Legend at bottom */}
        {!collapsed && !showHostDetail && <Legend />}

        {/* Resize handle on the sidebar's right edge.
            - Drag to resize, double-click to reset to default width.
            - Hidden when sidebar is collapsed (no width to drag).
            - Slim 4px hit area with a wider hover indicator so the bar is
              easy to find without taking visual real estate. */}
        {!collapsed && (
          <div
            onMouseDown={handleResizeStart}
            onDoubleClick={handleResizeReset}
            title="Drag to resize · double-click to reset"
            className={`absolute top-0 right-0 h-full w-1 cursor-ew-resize z-30 ${
              resizing
                ? 'bg-indigo-500'
                : 'bg-transparent hover:bg-indigo-500/60'
            }`}
          />
        )}
      </div>

      {/* Main graph canvas */}
      <div className="flex-1 relative">
        <GraphCanvas
          key={graphKey}
          selectedHost={selectedHost}
          onSelectHost={handleSelectHost}
          highlightPathIps={selectedPathIps}
          onClearPath={handleClearPath}
          onDataChanged={bumpDataVersion}
          refreshKey={dataVersion}
        />
      </div>
    </div>
  );
}
