import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Copy, Check, Trash2, ShieldCheck, Database, KeyRound, Lock } from 'lucide-react';
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

  // 30-second clipboard countdown
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

  const renderCategoryIcon = () => {
    switch (secret.category) {
      case 'database':
        return <Database className="w-3.5 h-3.5 text-burnrate-ample" />;
      case 'token':
        return <Lock className="w-3.5 h-3.5 text-burnrate-watch" />;
      case 'api-key':
      default:
        return <KeyRound className="w-3.5 h-3.5 text-[#808080]" />;
    }
  };

  return (
    <div className="relative group bg-surface hover:bg-surface-hover rounded-lg border border-border-subtle hover:border-border-track transition-all duration-150 ease-spring active:scale-[0.99] p-3.5 select-none shadow-card">
      {/* Burnrate-style hairline countdown progress bar */}
      {isCopied && (
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-border-track overflow-hidden rounded-t-lg">
          <div
            className="h-full bg-burnrate-ample shadow-glow-ample transition-all duration-1000 ease-linear"
            style={{ width: `${(copyTimeLeft / 30) * 100}%` }}
          />
        </div>
      )}

      {/* Top Header: Key Name, Scope Badge, and Hardware Verification */}
      <div className="flex items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="p-1 rounded bg-surface-active text-zinc-300 flex-shrink-0 border border-border-subtle">
            {renderCategoryIcon()}
          </span>
          <span className="font-mono text-xs font-semibold text-white tracking-tight truncate select-text">
            {secret.key}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {secret.scope === 'project' ? (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-active text-zinc-300 border border-border-subtle">
              {secret.project || 'project'}
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-active text-zinc-300 border border-border-subtle font-medium">
              GLOBAL
            </span>
          )}

          <span className="hidden sm:inline-flex items-center gap-1 text-[10px] text-[#808080]">
            <ShieldCheck className="w-3 h-3 text-burnrate-ample" />
            Keychain
          </span>
        </div>
      </div>

      {/* Value Row & Quick Actions */}
      <div className="flex items-center justify-between gap-3 pt-2.5 border-t border-border-subtle">
        {/* Value Display */}
        <div className="min-w-0 flex-1 font-mono text-xs text-[#808080] select-text truncate">
          {isLoadingReveal ? (
            <span className="text-[#6E6E73] animate-pulse">Decrypting with Secure Enclave...</span>
          ) : isRevealed && revealedValue ? (
            <span className="text-white font-medium break-all">{revealedValue}</span>
          ) : (
            <span className="text-[#808080] tracking-wider font-mono">
              {secret.maskedValue}
            </span>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {/* Reveal Button */}
          <button
            onClick={handleToggleReveal}
            disabled={isLoadingReveal}
            className={`p-1.5 rounded-md transition-all duration-150 ease-spring cursor-pointer border ${
              isRevealed
                ? 'bg-surface-active text-white border-border-track'
                : 'bg-surface hover:bg-surface-hover text-[#808080] hover:text-white border-border-subtle'
            }`}
            title={isRevealed ? 'Hide secret value' : 'Decrypt & reveal value'}
          >
            {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>

          {/* Copy Button with Burnrate Ample Accent */}
          <button
            onClick={handleCopy}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono transition-all duration-150 ease-spring cursor-pointer border ${
              isCopied
                ? 'bg-[#00FF88]/10 text-burnrate-ample border-[#00FF88]/40 shadow-glow-ample font-semibold'
                : 'bg-surface hover:bg-surface-hover text-zinc-300 hover:text-white border-border-subtle'
            }`}
            title="Copy to clipboard (auto-wipes in 30s)"
          >
            {isCopied ? (
              <>
                <Check className="w-3.5 h-3.5 text-burnrate-ample stroke-[2.5]" />
                <span>Copied ({copyTimeLeft}s)</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy</span>
              </>
            )}
          </button>

          {/* Delete Button with Critical Accent */}
          {isDeleting ? (
            <div className="flex items-center gap-1 bg-[#FF3F00]/10 p-0.5 rounded-md border border-burnrate-critical/50">
              <button
                onClick={handleDeleteConfirm}
                className="px-2 py-0.5 text-[10px] font-mono font-bold text-burnrate-critical hover:text-white cursor-pointer"
                title="Confirm deletion"
              >
                Confirm
              </button>
              <button
                onClick={() => setIsDeleting(false)}
                className="px-1.5 py-0.5 text-[10px] font-mono text-[#808080] hover:text-white cursor-pointer"
                title="Cancel deletion"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setIsDeleting(true)}
              className="p-1.5 rounded-md text-[#808080] hover:text-burnrate-critical hover:bg-[#FF3F00]/10 border border-transparent hover:border-burnrate-critical/30 transition-colors cursor-pointer"
              title="Delete secret from hardware store"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
