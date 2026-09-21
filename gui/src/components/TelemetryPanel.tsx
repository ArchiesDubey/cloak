import React from 'react';
import { Cpu, Activity, Terminal, RefreshCw } from 'lucide-react';
import { ProxyStatus, SecurityStatus } from '../types';

interface TelemetryPanelProps {
  proxyStatus: ProxyStatus;
  securityStatus: SecurityStatus;
  totalSecretsCount: number;
  onSimulateJit: () => void;
}

export const TelemetryPanel: React.FC<TelemetryPanelProps> = ({
  proxyStatus,
  securityStatus,
  totalSecretsCount,
  onSimulateJit,
}) => {
  return (
    <aside className="w-80 flex-shrink-0 flex flex-col gap-3 p-3 bg-surface/80 rounded-lg border border-subpixel font-mono select-none">
      {/* Hardware Keystore Telemetry */}
      <div className="p-3 bg-inset rounded border border-subpixel space-y-2.5">
        <div className="flex items-center justify-between text-xs font-bold text-gray-200">
          <span className="flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-radar-core" />
            ENCLAVE ENCRYPTION
          </span>
          <span className="text-[10px] text-radar-glow px-1.5 py-0.2 rounded bg-radar-dim border border-radar-border">
            SECURE
          </span>
        </div>

        <div className="space-y-1.5 text-[11px] text-gray-400">
          <div className="flex justify-between">
            <span>Hardware Backend:</span>
            <span className="text-gray-200 truncate max-w-[130px]" title={securityStatus.hardwareBackend}>
              Apple Keychain
            </span>
          </div>
          <div className="flex justify-between">
            <span>Auth Factor:</span>
            <span className="text-radar-glow">{securityStatus.biometricType}</span>
          </div>
          <div className="flex justify-between">
            <span>Core Dumps:</span>
            <span className="text-emerald-400">RLIMIT_CORE = 0</span>
          </div>
          <div className="flex justify-between">
            <span>Zeroize Memory:</span>
            <span className="text-emerald-400">ZeroizeOnDrop</span>
          </div>
          <div className="flex justify-between pt-1 border-t border-white/5">
            <span>Vault Items:</span>
            <span className="text-gray-200 font-bold">{totalSecretsCount} keys active</span>
          </div>
        </div>
      </div>

      {/* Proxy Intercept Metrics */}
      <div className="p-3 bg-inset rounded border border-subpixel space-y-2.5">
        <div className="flex items-center justify-between text-xs font-bold text-gray-200">
          <span className="flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-radar-core" />
            PROXY INTERCEPTOR
          </span>
          <span
            className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
              proxyStatus.running
                ? 'bg-radar-dim text-radar-glow border border-radar-border'
                : 'bg-black/40 text-gray-400'
            }`}
          >
            {proxyStatus.running ? '127.0.0.1:4141' : 'STOPPED'}
          </span>
        </div>

        <div className="space-y-1.5 text-[11px] text-gray-400">
          <div className="flex justify-between">
            <span>Handled Intercepts:</span>
            <span className="text-gray-200 font-bold">{proxyStatus.interceptCount}</span>
          </div>
          {proxyStatus.lastIntercept && (
            <div className="flex justify-between">
              <span>Last Request:</span>
              <span className="text-radar-glow text-[10px]">
                {proxyStatus.lastIntercept.agent} ({proxyStatus.lastIntercept.timestamp})
              </span>
            </div>
          )}
          <div className="flex justify-between">
            <span>Socket Mode:</span>
            <span className="text-gray-300">In-Flight Hold (Zero-Reset)</span>
          </div>
        </div>

        {/* Action button to simulate JIT agent request */}
        <button
          onClick={onSimulateJit}
          className="w-full mt-2 flex items-center justify-center gap-1.5 py-1.5 rounded bg-surface hover:bg-elevated text-radar-glow border border-radar-border/70 text-[11px] font-semibold transition-all hover:border-radar-core cursor-pointer active:scale-98"
          title="Simulate an AI agent (Claude Code / Aider) requesting a missing key"
        >
          <RefreshCw className="w-3 h-3 text-radar-core" />
          <span>SIMULATE JIT AGENT EVENT</span>
        </button>
      </div>

      {/* Quick Shell Injection Guide */}
      <div className="p-3 bg-inset rounded border border-subpixel space-y-2 flex-1">
        <div className="flex items-center gap-1.5 text-xs font-bold text-gray-300">
          <Terminal className="w-3.5 h-3.5 text-radar-core" />
          PROCESS INJECTOR
        </div>
        <p className="text-[10px] text-gray-400 leading-normal">
          Pass credentials directly into child process memory without writing .env files to disk:
        </p>
        <div className="p-2 rounded bg-black/50 border border-white/5 text-[10px] text-radar-glow font-mono select-text">
          <code>$ cloak run -- npm test</code>
        </div>
        <div className="p-2 rounded bg-black/50 border border-white/5 text-[10px] text-radar-glow font-mono select-text">
          <code>$ cloak proxy</code>
        </div>
      </div>
    </aside>
  );
};
