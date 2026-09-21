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
            <div className="w-7 h-7 rounded-lg bg-surface flex items-center justify-center border border-border-subtle text-white">
              <KeyRound className="w-3.5 h-3.5 text-zinc-300" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-semibold text-sm tracking-tight text-white">Cloak</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border-subtle text-zinc-400 font-mono">
                  v0.1
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Vault Navigation List */}
        <div className="p-3 space-y-1">
          <div className="px-2 pt-2 pb-1 text-[11px] font-medium tracking-wider text-zinc-400 uppercase">
            Vault Scopes
          </div>

          {/* All Secrets */}
          <button
            onClick={() => {
              onSelectScope('all');
            }}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
              currentScope === 'all'
                ? 'bg-surface text-white border border-border-subtle'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-surface-hover'
            }`}
          >
            <div className="flex items-center gap-2">
              <KeyRound className="w-3.5 h-3.5 text-zinc-400" />
              <span>All Secrets</span>
            </div>
            <span className="text-[11px] font-mono text-zinc-400">
              {counts.all}
            </span>
          </button>

          {/* Global (Keychain) */}
          <button
            onClick={() => {
              onSelectScope('global');
            }}
            className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
              currentScope === 'global'
                ? 'bg-surface text-white border border-border-subtle'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-surface-hover'
            }`}
          >
            <div className="flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-zinc-400" />
              <span>Global (Keychain)</span>
            </div>
            <span className="text-[11px] font-mono text-zinc-400">
              {counts.global}
            </span>
          </button>

          {/* Project Scopes Section */}
          <div className="pt-3">
            <div className="px-2 pb-1 text-[11px] font-medium tracking-wider text-zinc-400 uppercase flex items-center justify-between">
              <span>Projects</span>
              <span className="text-[10px] font-mono text-zinc-400">{projectList.length}</span>
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
                  className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    isSelected
                      ? 'bg-surface text-white border border-border-subtle'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-surface-hover'
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FolderGit2 className="w-3.5 h-3.5 text-zinc-400 flex-shrink-0" />
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
          className="w-full flex items-center justify-between p-2 rounded-md bg-surface hover:bg-surface-hover border border-border-subtle text-left transition-colors cursor-pointer"
          title="Toggle Hardware Keystore lock"
        >
          <div className="flex items-center gap-2">
            {securityStatus.isUnlocked ? (
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            )}
            <div className="flex flex-col">
              <span className="text-[11px] font-medium text-zinc-200">
                {securityStatus.isUnlocked ? 'Hardware Enclave' : 'Vault Locked'}
              </span>
              <span className="text-[10px] text-zinc-400 font-mono">
                {securityStatus.biometricType}
              </span>
            </div>
          </div>
          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-active text-zinc-300">
            {securityStatus.isUnlocked ? 'Active' : 'Locked'}
          </span>
        </button>

        {/* Local Proxy Status Card */}
        <button
          onClick={onToggleProxy}
          className="w-full flex items-center justify-between p-2 rounded-md bg-surface hover:bg-surface-hover border border-border-subtle text-left transition-colors cursor-pointer"
          title="Toggle Local AI Loopback Proxy"
        >
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${proxyStatus.running ? 'bg-emerald-500 shadow-sm' : 'bg-zinc-600'}`} />
            <div className="flex flex-col">
              <span className="text-[11px] font-medium text-zinc-200">
                AI Proxy :{proxyStatus.port}
              </span>
              <span className="text-[10px] text-zinc-400">
                {proxyStatus.running ? '127.0.0.1 loopback' : 'Inactive'}
              </span>
            </div>
          </div>
          <span
            className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
              proxyStatus.running
                ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60'
                : 'bg-surface-active text-zinc-400'
            }`}
          >
            {proxyStatus.running ? 'Running' : 'Off'}
          </span>
        </button>

        {/* Optional Simulate JIT Button for Testing */}
        <button
          onClick={onSimulateJit}
          className="w-full flex items-center justify-between py-1.5 px-2 rounded text-[11px] text-zinc-400 hover:text-zinc-200 hover:bg-surface-hover transition-colors cursor-pointer"
          title="Simulate an agent request intercept for testing"
        >
          <div className="flex items-center gap-1.5">
            <Sparkles className="w-3 h-3 text-zinc-400" />
            <span>Test JIT Prompt</span>
          </div>
          {pendingJitCount > 0 && (
            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300">
              {pendingJitCount}
            </span>
          )}
        </button>
      </div>
    </aside>
  );
};
