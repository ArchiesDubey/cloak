import React, { useEffect } from 'react';
import { Bot, Terminal, X, Shield, KeyRound } from 'lucide-react';
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md select-none">
      <div className="relative w-full max-w-md bg-surface rounded-xl border border-border-track shadow-modal overflow-hidden animate-fade-in">
        {/* Modal Top Banner */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-subtle">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-surface-active flex items-center justify-center border border-border-subtle text-white">
              <Shield className="w-4 h-4 text-zinc-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold text-sm text-white">
                  Agent Credential Request
                </h3>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#00FF88]/10 text-burnrate-ample border border-[#00FF88]/30 font-semibold">
                  Paused
                </span>
              </div>
              <p className="text-xs text-[#808080]">
                In-flight HTTP intercept via 127.0.0.1:4141
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-[#808080] hover:text-white hover:bg-surface-hover transition-colors cursor-pointer"
            title="Dismiss (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Request Inspection Content */}
        <div className="p-5 space-y-4">
          <div className="p-3.5 rounded-lg bg-surface-active/60 border border-border-subtle space-y-2.5 text-xs">
            {/* Agent / Process Row */}
            <div className="flex items-center justify-between">
              <span className="text-[#808080] flex items-center gap-1.5">
                <Bot className="w-3.5 h-3.5 text-[#6E6E73]" />
                Requesting Agent
              </span>
              <span className="font-mono text-white font-medium">
                {request.agent} {request.processPid ? `(PID: ${request.processPid})` : ''}
              </span>
            </div>

            {/* Target Endpoint */}
            <div className="flex items-center justify-between">
              <span className="text-[#808080] flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-[#6E6E73]" />
                Target Endpoint
              </span>
              <span className="text-zinc-300 font-mono text-[11px] truncate max-w-[220px]">
                {request.targetEndpoint}
              </span>
            </div>

            {/* Requested Credential */}
            <div className="flex items-center justify-between pt-2 border-t border-border-subtle">
              <span className="text-white font-medium flex items-center gap-1.5">
                <KeyRound className="w-3.5 h-3.5 text-zinc-400" />
                Requested Key
              </span>
              <span className="text-white font-mono font-bold text-xs bg-surface px-2 py-0.5 rounded border border-border-track shadow-sm">
                {request.key}
              </span>
            </div>
          </div>

          <p className="text-xs text-[#808080] leading-relaxed">
            The agent initiated an outbound AI call missing credentials. Authorizing injects the key directly into process memory without session restart.
          </p>

          {/* Action Decision Buttons */}
          <div className="grid grid-cols-3 gap-2 pt-2">
            {/* Deny Button */}
            <button
              onClick={() => onRespond(request.id, 'deny')}
              className="flex flex-col items-center justify-center p-2.5 rounded-lg bg-surface hover:bg-[#FF3F00]/10 border border-border-subtle hover:border-burnrate-critical/40 text-zinc-300 hover:text-burnrate-critical transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer"
            >
              <span className="text-xs font-semibold">Deny</span>
              <span className="text-[10px] text-[#6E6E73] mt-0.5 font-mono">[D]</span>
            </button>

            {/* Allow Once Button */}
            <button
              onClick={() => onRespond(request.id, 'once')}
              className="flex flex-col items-center justify-center p-2.5 rounded-lg bg-surface hover:bg-surface-hover border border-border-subtle hover:border-border-track text-zinc-200 hover:text-white transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer"
            >
              <span className="text-xs font-semibold">Allow Once</span>
              <span className="text-[10px] text-[#6E6E73] mt-0.5 font-mono">[O]</span>
            </button>

            {/* Always Allow Button */}
            <button
              onClick={() => onRespond(request.id, 'always')}
              className="flex flex-col items-center justify-center p-2.5 rounded-lg bg-white hover:bg-zinc-200 text-black transition-all duration-150 ease-spring active:scale-[0.98] cursor-pointer font-bold shadow-sm"
            >
              <span className="text-xs font-bold">Always Allow</span>
              <span className="text-[10px] text-zinc-600 mt-0.5 font-mono">[A]</span>
            </button>
          </div>
        </div>

        {/* Footer info */}
        <div className="px-5 py-2.5 bg-surface-active/40 border-t border-border-subtle flex items-center justify-between text-[11px] text-[#6E6E73]">
          <span>Shortcuts: [D] Deny • [O] Once • [A] Always</span>
          <span className="text-burnrate-ample font-semibold">Verified</span>
        </div>
      </div>
    </div>
  );
};
