import React, { useEffect } from 'react';
import { Bot, Radio, Terminal, Check, X, ShieldCheck, Zap } from 'lucide-react';
import { JitRequest } from '../types';

interface JitApprovalModalProps {
  request: JitRequest | null;
  onRespond: (requestId: string, action: 'deny' | 'once' | 'always') => Promise<void>;
  onClose: () => void;
}

export const JitApprovalModal: React.FC<JitApprovalModalProps> = ({
  request,
  onRespond,
  onClose,
}) => {
  useEffect(() => {
    if (!request) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'd' || e.key === 'D') {
        e.preventDefault();
        onRespond(request.id, 'deny');
      } else if (e.key === 'o' || e.key === 'O') {
        e.preventDefault();
        onRespond(request.id, 'once');
      } else if (e.key === 'a' || e.key === 'A') {
        e.preventDefault();
        onRespond(request.id, 'always');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [request, onRespond, onClose]);

  if (!request) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fadeIn select-none">
      <div className="relative w-full max-w-lg bg-surface rounded-lg border-2 border-radar-core shadow-2xl overflow-hidden shadow-radar-glow">
        {/* Animated Warning Bar */}
        <div className="h-1.5 bg-radar-core animate-pulse" />

        {/* Modal Top Banner */}
        <div className="flex items-center justify-between px-5 py-3 bg-inset/90 border-b border-subpixel">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded bg-radar-dim flex items-center justify-center border border-radar-border">
              <Radio className="w-3.5 h-3.5 text-radar-glow animate-spin" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-black tracking-widest text-radar-glow uppercase">
                  [ JIT SECURITY INTERCEPT ]
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-radar-border text-radar-glow font-bold animate-pulse">
                  SOCKET PAUSED
                </span>
              </div>
              <p className="text-[10px] font-mono text-gray-400">
                HTTP request paused in-flight &bull; Proxy 127.0.0.1:4141
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-elevated cursor-pointer"
            title="Dismiss HUD (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Request Inspection Content */}
        <div className="p-5 space-y-4">
          <div className="p-3 rounded bg-inset border border-subpixel space-y-2 font-mono text-xs">
            {/* Agent / Process Row */}
            <div className="flex items-center justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Bot className="w-3.5 h-3.5 text-radar-core" />
                REQUESTING AGENT:
              </span>
              <span className="text-gray-100 font-bold bg-surface px-2 py-0.5 rounded border border-subpixel">
                {request.agent} {request.processPid ? `(PID: ${request.processPid})` : ''}
              </span>
            </div>

            {/* Target Endpoint */}
            <div className="flex items-center justify-between">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-radar-core" />
                TARGET ENDPOINT:
              </span>
              <span className="text-gray-300 font-mono text-[11px] truncate max-w-[280px]">
                {request.targetEndpoint}
              </span>
            </div>

            {/* Requested Credential */}
            <div className="flex items-center justify-between pt-1 border-t border-white/5">
              <span className="text-gray-400 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-radar-glow" />
                REQUESTED KEY:
              </span>
              <span className="text-radar-glow font-mono font-bold text-sm bg-radar-dim px-2 py-0.5 rounded border border-radar-border">
                {request.key}
              </span>
            </div>
          </div>

          <p className="text-xs text-gray-300 font-mono leading-relaxed">
            The agent initiated an outbound AI call missing credentials. Injecting authorization directly into process memory without session restart.
          </p>

          {/* Action Decision Buttons */}
          <div className="grid grid-cols-3 gap-2.5 pt-2">
            {/* Deny Button */}
            <button
              onClick={() => onRespond(request.id, 'deny')}
              className="flex flex-col items-center justify-center p-3 rounded bg-inset hover:bg-red-950/40 border border-subpixel hover:border-red-600/80 text-gray-300 hover:text-red-200 transition-all cursor-pointer group active:scale-95"
            >
              <div className="flex items-center gap-1 font-mono text-xs font-bold">
                <X className="w-3.5 h-3.5 text-red-400" />
                <span>DENY</span>
              </div>
              <span className="text-[9px] font-mono text-gray-400 group-hover:text-red-300 mt-0.5">
                Drop Socket [D]
              </span>
            </button>

            {/* Allow Once Button */}
            <button
              onClick={() => onRespond(request.id, 'once')}
              className="flex flex-col items-center justify-center p-3 rounded bg-elevated hover:bg-inset border border-subpixel hover:border-radar-border text-gray-200 hover:text-white transition-all cursor-pointer group active:scale-95"
            >
              <div className="flex items-center gap-1 font-mono text-xs font-bold text-gray-100">
                <Check className="w-3.5 h-3.5 text-radar-core" />
                <span>ALLOW ONCE</span>
              </div>
              <span className="text-[9px] font-mono text-gray-400 group-hover:text-gray-300 mt-0.5">
                This Request [O]
              </span>
            </button>

            {/* Always Allow Button */}
            <button
              onClick={() => onRespond(request.id, 'always')}
              className="flex flex-col items-center justify-center p-3 rounded bg-radar-core hover:bg-radar-glow border border-amber-300 text-black font-bold transition-all cursor-pointer shadow-radar-glow active:scale-95 group"
            >
              <div className="flex items-center gap-1 font-mono text-xs font-black">
                <ShieldCheck className="w-3.5 h-3.5 stroke-[2.5]" />
                <span>ALWAYS ALLOW</span>
              </div>
              <span className="text-[9px] font-mono text-amber-950 group-hover:text-black mt-0.5 font-semibold">
                Remember Agent [A]
              </span>
            </button>
          </div>
        </div>

        {/* Footer info */}
        <div className="px-5 py-2 bg-inset/40 border-t border-subpixel flex items-center justify-between text-[10px] font-mono text-gray-400">
          <span>Shortcuts: [D] Deny &bull; [O] Once &bull; [A] Always &bull; [Esc] Dismiss</span>
          <span className="text-radar-glow font-mono">ENCLAVE VERIFIED</span>
        </div>
      </div>
    </div>
  );
};
