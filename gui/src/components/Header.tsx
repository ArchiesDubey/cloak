import React from 'react';
import { ShieldCheck, ShieldAlert, Maximize2, Minimize2, Radio } from 'lucide-react';
import { ProxyStatus, SecurityStatus } from '../types';

interface HeaderProps {
  isCompact: boolean;
  onToggleCompact: () => void;
  proxyStatus: ProxyStatus;
  onToggleProxy: () => void;
  securityStatus: SecurityStatus;
  onToggleLock: () => void;
  pendingJitCount: number;
  onOpenJitModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  isCompact,
  onToggleCompact,
  proxyStatus,
  onToggleProxy,
  securityStatus,
  onToggleLock,
  pendingJitCount,
  onOpenJitModal,
}) => {
  return (
    <header className="sticky top-0 z-30 flex items-center justify-between px-4 py-2.5 bg-surface/95 backdrop-blur border-b border-subpixel select-none">
      {/* Brand & System Status */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center w-6 h-6 rounded bg-inset border border-radar-border/60 shadow-subtle-inset">
            <div className="w-2.5 h-2.5 rounded-sm bg-radar-core shadow-radar-glow animate-pulse-slow" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-xs tracking-widest font-black text-gray-100 uppercase">
                [ CLOAK ]
              </span>
              <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-inset text-radar-glow border border-white/5 font-semibold">
                v0.6.0
              </span>
            </div>
            <span className="text-[9px] font-mono text-gray-400 leading-none">
              LOCAL-FIRST HARDWARE VAULT
            </span>
          </div>
        </div>

        {/* Hardware Keystore Indicator */}
        <button
          onClick={onToggleLock}
          title={`Keystore: ${securityStatus.hardwareBackend} (${securityStatus.isUnlocked ? 'Unlocked' : 'Locked'}). Click to toggle.`}
          className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded bg-inset/80 hover:bg-inset active:scale-95 transition-all border border-subpixel group cursor-pointer"
        >
          {securityStatus.isUnlocked ? (
            <ShieldCheck className="w-3.5 h-3.5 text-radar-core group-hover:text-radar-glow transition-colors" />
          ) : (
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
          )}
          <span className="text-[10px] font-mono text-gray-300">
            {securityStatus.isUnlocked ? (
              <span className="text-gray-300 group-hover:text-radar-glow">
                [{securityStatus.biometricType.toUpperCase().includes('WINDOWS') ? 'WIN-HELLO' : 'VAULT'}: <span className="text-radar-core font-bold">UNLOCKED</span>]
              </span>
            ) : (
              <span className="text-red-400 font-bold">[VAULT: LOCKED]</span>
            )}
          </span>
        </button>
      </div>

      {/* Right Controls: Proxy Pill + JIT Alert + Window Size */}
      <div className="flex items-center gap-2">
        {/* JIT Pending Alert Pill */}
        {pendingJitCount > 0 && (
          <button
            onClick={onOpenJitModal}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-radar-core/15 border border-radar-border text-radar-glow hover:bg-radar-core/25 transition-all animate-pulse"
            title="Pending Just-In-Time Secret Requests"
          >
            <Radio className="w-3.5 h-3.5 text-radar-core animate-spin" />
            <span className="font-mono text-[11px] font-bold tracking-tight">
              JIT REQ ({pendingJitCount})
            </span>
          </button>
        )}

        {/* Proxy State Toggle */}
        <button
          onClick={onToggleProxy}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono transition-all border cursor-pointer active:translate-y-px ${
            proxyStatus.running
              ? 'bg-inset text-gray-200 border-radar-border/80 hover:border-radar-core shadow-radar-glow-sm'
              : 'bg-inset/50 text-gray-400 border-subpixel hover:text-gray-300'
          }`}
          title={`Loopback Proxy 127.0.0.1:${proxyStatus.port} - Click to toggle`}
        >
          <div
            className={`w-1.5 h-1.5 rounded-full ${
              proxyStatus.running ? 'bg-radar-core shadow-radar-glow' : 'bg-gray-600'
            }`}
          />
          <span className="font-semibold tracking-wider">
            PROXY:{proxyStatus.port}
          </span>
          <span
            className={`text-[9px] px-1 rounded uppercase font-bold ${
              proxyStatus.running
                ? 'bg-radar-border text-radar-glow'
                : 'bg-black/40 text-gray-400'
            }`}
          >
            {proxyStatus.running ? 'ACTIVE' : 'OFF'}
          </span>
        </button>

        {/* Mode Switcher (Compact HUD vs Expanded Desktop) */}
        <button
          onClick={onToggleCompact}
          className="p-1.5 rounded bg-inset hover:bg-elevated text-gray-400 hover:text-gray-200 border border-subpixel transition-all active:scale-95 cursor-pointer"
          title={isCompact ? 'Expand to Desktop Dashboard (⌘E)' : 'Collapse to Compact HUD (⌘E)'}
        >
          {isCompact ? (
            <Maximize2 className="w-3.5 h-3.5" />
          ) : (
            <Minimize2 className="w-3.5 h-3.5" />
          )}
        </button>
      </div>
    </header>
  );
};
