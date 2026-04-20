import { useState, useCallback } from 'react';
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

export function Layout() {
  const [activeTab, setActiveTab] = useState<Tab>('stats');
  const [collapsed, setCollapsed] = useState(false);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [showHostDetail, setShowHostDetail] = useState(false);
  const [graphKey, setGraphKey] = useState(0);
  const [dataVersion, setDataVersion] = useState(0);
  const [selectedPathIps, setSelectedPathIps] = useState<string[] | null>(null);

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
      {/* Sidebar */}
      <div
        className={`flex flex-col border-r border-gray-800 bg-gray-900 transition-all duration-200 ${
          collapsed ? 'w-12' : 'w-96'
        }`}
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
