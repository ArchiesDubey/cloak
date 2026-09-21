import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Copy, Check, Trash2, ShieldCheck, Database, KeyRound, Lock, AlertTriangle } from 'lucide-react';
import { SecretItem } from '../types';

interface SecretCardProps {
  secret: SecretItem;
  onRevealToggle: (key: string, currentRevealed: boolean) => Promise<string | void>;
  onDelete: (key: string) => Promise<void>;
  onCopySuccess: (key: string) => void;
}

export const SecretCard: React.FC<SecretCardProps> = ({
  secret,
  onRevealToggle,
  onDelete,
  onCopySuccess,
}) => {
  const [isRevealed, setIsRevealed] = useState(false);
  const [revealedValue, setRevealedValue] = useState<string | null>(null);
  const [isLoadingReveal, setIsLoadingReveal] = useState(false);
  const [isCopied, setIsCopied] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [copyTimeLeft, setCopyTimeLeft] = useState<number>(0);

  // 30-second clipboard hairline countdown
  useEffect(() => {
    let timer: ReturnType<typeof setInterval>;
    if (isCopied) {
      setCopyTimeLeft(30);
      timer = setInterval(() => {
        setCopyTimeLeft((prev) => {
          if (prev <= 1) {
            setIsCopied(false);
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [isCopied]);

  const handleToggleReveal = async () => {
    if (isRevealed) {
      setIsRevealed(false);
      setRevealedValue(null);
      return;
    }

    try {
      setIsLoadingReveal(true);
      const val = await onRevealToggle(secret.key, isRevealed);
      if (typeof val === 'string') {
        setRevealedValue(val);
      }
      setIsRevealed(true);
    } catch (err) {
      console.error('Failed to reveal secret', err);
    } finally {
      setIsLoadingReveal(false);
    }
  };

  const handleCopy = async () => {
    try {
      // Get the real value if available or reveal it to copy
      const valToCopy = secret.fullValue || revealedValue || secret.maskedValue;
      await navigator.clipboard.writeText(valToCopy);
      setIsCopied(true);
      onCopySuccess(secret.key);
    } catch (err) {
      console.error('Failed to copy to clipboard', err);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!isDeleting) {
      setIsDeleting(true);
      return;
    }
    await onDelete(secret.key);
  };

  // Helper icon for category
  const renderCategoryIcon = () => {
    switch (secret.category) {
      case 'database':
        return <Database className="w-3 h-3 text-cyan-400/80" />;
      case 'token':
        return <Lock className="w-3 h-3 text-radar-core" />;
      case 'api-key':
      default:
        return <KeyRound className="w-3 h-3 text-radar-glow" />;
    }
  };

  return (
    <div
      className={`relative group bg-surface hover:bg-elevated transition-all rounded border ${
        isCopied
          ? 'border-radar-border shadow-radar-glow-sm'
          : 'border-subpixel hover:border-subpixel-hover'
      } overflow-hidden`}
    >
      {/* 30-Second Hairline Countdown Bar */}
      {isCopied && (
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-inset overflow-hidden z-10">
          <div
            className="h-full bg-gradient-to-r from-radar-core via-radar-glow to-amber-300 transition-all duration-1000 ease-linear"
            style={{ width: `${(copyTimeLeft / 30) * 100}%` }}
          />
        </div>
      )}

      <div className="p-3">
        {/* Top Line: Key Name + Badges + Scope */}
        <div className="flex items-center justify-between gap-2 mb-1.5">
          <div className="flex items-center gap-2 min-w-0">
            <span className="p-1 rounded bg-inset border border-subpixel flex-shrink-0">
              {renderCategoryIcon()}
            </span>
            <span className="font-mono text-xs font-bold text-gray-100 tracking-tight truncate select-text">
              {secret.key}
            </span>
          </div>

          <div className="flex items-center gap-1.5 flex-shrink-0">
            {secret.scope === 'project' ? (
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-inset text-amber-300 border border-white/5">
                {secret.project || 'project'}
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-radar-dim text-radar-glow border border-radar-border/40 font-semibold">
                GLOBAL
              </span>
            )}

            <span className="hidden sm:inline-flex items-center gap-1 text-[9px] font-mono text-gray-400">
              <ShieldCheck className="w-2.5 h-2.5 text-radar-core" />
              KEYCHAIN
            </span>
          </div>
        </div>

        {/* Value Display Row */}
        <div className="flex items-center justify-between gap-2 mt-2 pt-2 border-t border-subpixel/60">
          <div className="min-w-0 flex-1 font-mono text-xs text-gray-400 select-text overflow-hidden text-ellipsis">
            {isLoadingReveal ? (
              <span className="text-gray-400 animate-pulse">[DECRYPTING VIA SECURE ENCLAVE...]</span>
            ) : isRevealed && revealedValue ? (
              <span className="text-radar-glow font-medium break-all">{revealedValue}</span>
            ) : (
              <span className="text-gray-400 tracking-wider select-none font-mono">
                {secret.maskedValue}
              </span>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-1 flex-shrink-0">
            {/* Reveal Button */}
            <button
              onClick={handleToggleReveal}
              disabled={isLoadingReveal}
              className={`p-1.5 rounded transition-all cursor-pointer border ${
                isRevealed
                  ? 'bg-radar-dim text-radar-glow border-radar-border'
                  : 'bg-inset text-gray-400 hover:text-gray-200 border-subpixel hover:bg-elevated'
              }`}
              title={isRevealed ? 'Hide secret value' : 'Decrypt & reveal value'}
            >
              {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </button>

            {/* Copy Button with Tactile Feedback */}
            <button
              onClick={handleCopy}
              className={`flex items-center gap-1 px-2 py-1.5 rounded text-[11px] font-mono transition-all cursor-pointer border active:scale-95 ${
                isCopied
                  ? 'bg-radar-core text-black font-bold border-radar-glow shadow-radar-glow-sm'
                  : 'bg-inset hover:bg-elevated text-gray-300 hover:text-white border-subpixel'
              }`}
              title="Copy to clipboard (auto-wipes in 30s)"
            >
              {isCopied ? (
                <>
                  <Check className="w-3.5 h-3.5 stroke-[3]" />
                  <span>COPIED ({copyTimeLeft}s)</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">COPY</span>
                </>
              )}
            </button>

            {/* Delete Button with Safety Confirm */}
            {isDeleting ? (
              <div className="flex items-center gap-1 animate-fadeIn">
                <button
                  onClick={handleDeleteConfirm}
                  className="px-2 py-1 rounded text-[10px] font-mono font-bold bg-red-900/60 text-red-200 border border-red-700 hover:bg-red-800 transition-colors cursor-pointer"
                  title="Confirm deletion from hardware store"
                >
                  CONFIRM?
                </button>
                <button
                  onClick={() => setIsDeleting(false)}
                  className="p-1 rounded text-gray-400 hover:text-gray-200 bg-inset border border-subpixel cursor-pointer"
                  title="Cancel deletion"
                >
                  ✕
                </button>
              </div>
            ) : (
              <button
                onClick={() => setIsDeleting(true)}
                className="p-1.5 rounded bg-inset text-gray-400 hover:text-red-400 hover:bg-red-950/20 border border-subpixel transition-colors cursor-pointer"
                title="Delete secret from vault"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Footer micro-details */}
        <div className="flex items-center justify-between text-[10px] font-mono text-gray-400 mt-2">
          <span>Synced: {secret.updatedAt}</span>
          {isCopied && (
            <span className="text-radar-glow animate-pulse text-[9px] flex items-center gap-1">
              <AlertTriangle className="w-2.5 h-2.5" />
              CLIPBOARD MEMORY PURGE ARMED
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
