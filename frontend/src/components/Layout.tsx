import { useState } from 'react';
import { Network, BarChart3, Shield, Crosshair, ChevronLeft, ChevronRight } from 'lucide-react';
import { StatsPanel } from './StatsPanel';
import { HostList } from './HostList';
import { AttackPaths } from './AttackPaths';
import { GraphCanvas } from './GraphCanvas';
import { Legend } from './Legend';

type Tab = 'stats' | 'hosts' | 'paths';

export function Layout() {
  const [activeTab, setActiveTab] = useState<Tab>('stats');
  const [collapsed, setCollapsed] = useState(false);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'stats', label: 'Dashboard', icon: <BarChart3 size={18} /> },
    { id: 'hosts', label: 'Hosts', icon: <Network size={18} /> },
    { id: 'paths', label: 'Attack Paths', icon: <Crosshair size={18} /> },
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
                onClick={() => setActiveTab(tab.id)}
                className={`flex flex-1 items-center justify-center gap-1.5 py-2.5 text-xs font-medium transition-colors ${
                  activeTab === tab.id
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
            {activeTab === 'stats' && <StatsPanel />}
            {activeTab === 'hosts' && <HostList onSelectHost={setSelectedHost} selectedHost={selectedHost} />}
            {activeTab === 'paths' && <AttackPaths />}
          </div>
        )}

        {/* Legend at bottom */}
        {!collapsed && <Legend />}
      </div>

      {/* Main graph canvas */}
      <div className="flex-1 relative">
        <GraphCanvas selectedHost={selectedHost} onSelectHost={setSelectedHost} />
      </div>
    </div>
  );
}
