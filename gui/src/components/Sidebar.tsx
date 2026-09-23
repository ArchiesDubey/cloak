import React from 'react';
import { ShieldCheck, ShieldAlert, KeyRound, Globe, FolderGit2, Sparkles } from 'lucide-react';
import { ScopeFilter, ProxyStatus, SecurityStatus } from '../types';

interface SidebarProps {
  currentScope: ScopeFilter;
  onSelectScope: (scope: ScopeFilter) => void;
  selectedProject: string | null;
  onSelectProject: (projectName: string) => void;
  projectList: string[];
  counts: {
    all: number;
    global: number;
    project: number;
  };
  proxyStatus: ProxyStatus;
  onToggleProxy: () => void;
  securityStatus: SecurityStatus;
  onToggleLock: () => void;
  onSimulateJit: () => void;
  pendingJitCount: number;
}

// Burnrate-inspired StatusRing: 3/4 animated circle at 1.4s period
const StatusRing: React.FC<{ active: boolean; color?: string }> = ({ active, color = '#00FF88' }) => {
  if (!active) {
    return (
      <svg className="w-3.5 h-3.5 flex-shrink-0" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="9" stroke="#6E6E73" strokeWidth="2.5" fill="none" />
      </svg>
    );
  }
  return (
    <svg className="w-3.5 h-3.5 animate-status-spin flex-shrink-0" viewBox="0 0 24 24">
      <circle
        cx="12"
        cy="12"
        r="9"
        stroke={color}
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeDasharray="42.4 14.1"
        fill="none"
      />
    </svg>
  );
};

export const Sidebar: React.FC<SidebarProps> = ({
  currentScope,
  onSelectScope,
  selectedProject,
  onSelectProject,
  projectList,
  counts,
  proxyStatus,
  onToggleProxy,
  securityStatus,
  onToggleLock,
  onSimulateJit,
  pendingJitCount,
}) => {
  return (
    <aside className="w-56 bg-sidebar border-r border-border-subtle flex flex-col justify-between select-none flex-shrink-0">
      {/* Top Header & Branding */}
      <div>
        <div className="p-4 border-b border-border-subtle flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <img src="/icon.png" alt="Cloak Logo" className="w-7 h-7 rounded-lg border border-border-subtle shadow-sm object-cover" />
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-semibold text-sm tracking-tight text-white">Cloak</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border-subtle text-[#808080] font-mono">
                  v0.5.2
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Vault Navigation List */}
        <div className="p-3 space-y-1">
          <div className="px-2 pt-2 pb-1 text-[11px] font-medium tracking-wider text-[#6E6E73] uppercase">
            Vault Scopes
          </div>

          {/* All Secrets */}
          <button
            onClick={() => onSelectScope('all')}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer ${
              currentScope === 'all'
                ? 'bg-surface text-white border border-border-subtle shadow-sm'
                : 'text-[#808080] hover:text-white hover:bg-surface-hover'
            }`}
          >
            <div className="flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-[#808080]" />
              <span>All Secrets</span>
            </div>
            <span className="text-[11px] font-mono text-[#808080]">
              {counts.all}
            </span>
          </button>

          {/* Global (Keychain) */}
          <button
            onClick={() => onSelectScope('global')}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer ${
              currentScope === 'global'
                ? 'bg-surface text-white border border-border-subtle shadow-sm'
                : 'text-[#808080] hover:text-white hover:bg-surface-hover'
            }`}
          >
            <div className="flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-[#808080]" />
              <span>Global (Keychain)</span>
            </div>
            <span className="text-[11px] font-mono text-[#808080]">
              {counts.global}
            </span>
          </button>

          {/* Project Scopes Section */}
          <div className="pt-3">
            <div className="px-2 pb-1 text-[11px] font-medium tracking-wider text-[#6E6E73] uppercase flex items-center justify-between">
              <span>Projects</span>
              <span className="text-[10px] font-mono text-[#808080]">{projectList.length}</span>
            </div>

            {projectList.map((proj) => {
              const isSelected = currentScope === 'project' && selectedProject === proj;
              return (
                <button
                  key={proj}
                  onClick={() => {
                    onSelectScope('project');
                    onSelectProject(proj);
                  }}
                  className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer ${
                    isSelected
                      ? 'bg-surface text-white border border-border-subtle shadow-sm'
                      : 'text-[#808080] hover:text-white hover:bg-surface-hover'
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FolderGit2 className="w-3.5 h-3.5 text-[#808080] flex-shrink-0" />
                    <span className="truncate font-mono text-[11px]">{proj}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Bottom Status & Hardware Telemetry */}
      <div className="p-3 border-t border-border-subtle space-y-2">
        {/* Keystore Status Card */}
        <button
          onClick={onToggleLock}
          className="w-full flex items-center justify-between p-2 rounded-lg bg-surface hover:bg-surface-hover border border-border-subtle text-left transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer"
          title="Toggle Hardware Keystore lock"
        >
          <div className="flex items-center gap-2">
            {securityStatus.isUnlocked ? (
              <ShieldCheck className="w-3.5 h-3.5 text-burnrate-ample" />
            ) : (
              <ShieldAlert className="w-3.5 h-3.5 text-burnrate-critical" />
            )}
            <div className="flex flex-col">
              <span className="text-[11px] font-medium text-white truncate max-w-[110px]" title={securityStatus.hardwareBackend}>
                {securityStatus.isUnlocked ? (securityStatus.hardwareBackend.includes('Windows') ? 'Windows Vault' : 'Hardware Vault') : 'Vault Locked'}
              </span>
              <span className="text-[10px] text-[#808080] font-mono truncate max-w-[110px]" title={securityStatus.biometricType}>
                {securityStatus.biometricType}
              </span>
            </div>
          </div>
          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-active text-white border border-border-subtle">
            {securityStatus.isUnlocked ? 'Active' : 'Locked'}
          </span>
        </button>

        {/* Local Proxy Status Card with Burnrate StatusRing */}
        <button
          onClick={onToggleProxy}
          className="w-full flex items-center justify-between p-2 rounded-lg bg-surface hover:bg-surface-hover border border-border-subtle text-left transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer"
          title="Toggle Local AI Loopback Proxy"
        >
          <div className="flex items-center gap-2.5">
            <StatusRing active={proxyStatus.running} color="#00FF88" />
            <div className="flex flex-col">
              <span className="text-[11px] font-medium text-white">
                AI Proxy :{proxyStatus.port}
              </span>
              <span className="text-[10px] text-[#808080]">
                {proxyStatus.running ? '127.0.0.1 loopback' : 'Inactive'}
              </span>
            </div>
          </div>
          <span
            className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
              proxyStatus.running
                ? 'bg-[#00FF88]/10 text-burnrate-ample border-[#00FF88]/30 font-semibold'
                : 'bg-surface-active text-[#808080] border-border-subtle'
            }`}
          >
            {proxyStatus.running ? 'Running' : 'Off'}
          </span>
        </button>

        {/* Optional Simulate JIT Button for Testing */}
        <button
          onClick={onSimulateJit}
          className="w-full flex items-center justify-between py-1.5 px-2 rounded-md text-[11px] text-[#808080] hover:text-white hover:bg-surface-hover transition-colors cursor-pointer"
          title="Simulate an agent request intercept for testing"
        >
          <div className="flex items-center gap-1.5">
            <Sparkles className="w-3 h-3 text-[#808080]" />
            <span>Test JIT Prompt</span>
          </div>
          {pendingJitCount > 0 && (
            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-[#F2FF00]/20 text-burnrate-watch border border-[#F2FF00]/30">
              {pendingJitCount}
            </span>
          )}
        </button>
      </div>
    </aside>
  );
};
