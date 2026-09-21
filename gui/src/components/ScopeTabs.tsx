import React from 'react';
import { Globe, FolderGit2, Layers } from 'lucide-react';
import { ScopeFilter } from '../types';

interface ScopeTabsProps {
  currentScope: ScopeFilter;
  onSelectScope: (scope: ScopeFilter) => void;
  counts: {
    all: number;
    global: number;
    project: number;
  };
  currentProjectName?: string;
}

export const ScopeTabs: React.FC<ScopeTabsProps> = ({
  currentScope,
  onSelectScope,
  counts,
  currentProjectName = 'cloak-core',
}) => {
  const tabs = [
    {
      id: 'global' as ScopeFilter,
      label: 'Global',
      icon: Globe,
      count: counts.global,
      subtext: 'OS Keychain',
    },
    {
      id: 'project' as ScopeFilter,
      label: 'Project',
      icon: FolderGit2,
      count: counts.project,
      subtext: currentProjectName,
    },
    {
      id: 'all' as ScopeFilter,
      label: 'All Vaults',
      icon: Layers,
      count: counts.all,
      subtext: 'Combined',
    },
  ];

  return (
    <div className="flex p-1 bg-inset/90 rounded-md border border-subpixel select-none">
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = currentScope === tab.id;

        return (
          <button
            key={tab.id}
            onClick={() => onSelectScope(tab.id)}
            className={`relative flex-1 flex items-center justify-between px-3 py-1.5 rounded transition-all text-left cursor-pointer group ${
              isActive
                ? 'bg-elevated text-gray-100 shadow-tactile border border-subpixel'
                : 'text-gray-400 hover:text-gray-200 hover:bg-surface/50 border border-transparent'
            }`}
          >
            {/* Active Amber Indicator Line */}
            {isActive && (
              <span className="absolute bottom-0 left-2 right-2 h-[2px] bg-radar-core shadow-radar-glow" />
            )}

            <div className="flex items-center gap-2">
              <Icon
                className={`w-3.5 h-3.5 transition-colors ${
                  isActive ? 'text-radar-core' : 'text-gray-400 group-hover:text-gray-300'
                }`}
              />
              <div className="flex flex-col">
                <span className="text-xs font-semibold tracking-wide">
                  {tab.label}
                </span>
                <span className="text-[9px] font-mono text-gray-400 truncate max-w-[85px]">
                  {tab.subtext}
                </span>
              </div>
            </div>

            <span
              className={`font-mono text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
                isActive
                  ? 'bg-radar-dim text-radar-glow border-radar-border font-bold'
                  : 'bg-black/30 text-gray-400 border-white/5'
              }`}
            >
              {tab.count}
            </span>
          </button>
        );
      })}
    </div>
  );
};
