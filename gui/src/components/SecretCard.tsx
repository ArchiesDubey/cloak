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
        return <Database className="w-3.5 h-3.5 text-sky-400" />;
      case 'token':
        return <Lock className="w-3.5 h-3.5 text-amber-400" />;
      case 'api-key':
      default:
        return <KeyRound className="w-3.5 h-3.5 text-zinc-400" />;
    }
  };

  return (
    <div className="relative group bg-surface hover:bg-surface-hover rounded-lg border border-border-subtle hover:border-border-hover transition-colors p-3.5 select-none">
      {/* Hairline clipboard countdown indicator */}
      {isCopied && (
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-zinc-800 overflow-hidden rounded-t-lg">
          <div
            className="h-full bg-emerald-500 transition-all duration-1000 ease-linear"
            style={{ width: `${(copyTimeLeft / 30) * 100}%` }}
          />
        </div>
      )}

      {/* Top Header: Key Name, Scope Badge, and Hardware Verification */}
      <div className="flex items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="p-1 rounded bg-surface-active text-zinc-300 flex-shrink-0">
            {renderCategoryIcon()}
          </span>
          <span className="font-mono text-xs font-semibold text-zinc-100 tracking-tight truncate select-text">
            {secret.key}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {secret.scope === 'project' ? (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800/80 text-zinc-300 border border-zinc-700/60">
              {secret.project || 'project'}
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800/80 text-zinc-300 border border-zinc-700/60 font-medium">
              GLOBAL
            </span>
          )}

          <span className="hidden sm:inline-flex items-center gap-1 text-[10px] text-zinc-400">
            <ShieldCheck className="w-3 h-3 text-emerald-500" />
            Keychain
          </span>
        </div>
      </div>

      {/* Value Row & Quick Actions */}
      <div className="flex items-center justify-between gap-3 pt-2 border-t border-border-subtle/60">
        {/* Value Display */}
        <div className="min-w-0 flex-1 font-mono text-xs text-zinc-400 select-text truncate">
          {isLoadingReveal ? (
            <span className="text-zinc-500 animate-pulse">Decrypting with Secure Enclave...</span>
          ) : isRevealed && revealedValue ? (
            <span className="text-zinc-100 font-medium break-all">{revealedValue}</span>
          ) : (
            <span className="text-zinc-400 tracking-wider font-mono">
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
            className={`p-1.5 rounded-md transition-colors cursor-pointer border ${
              isRevealed
                ? 'bg-zinc-800 text-white border-zinc-700'
                : 'bg-surface hover:bg-surface-active text-zinc-400 hover:text-zinc-200 border-border-subtle'
            }`}
            title={isRevealed ? 'Hide secret value' : 'Decrypt & reveal value'}
          >
            {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>

          {/* Copy Button */}
          <button
            onClick={handleCopy}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono transition-colors cursor-pointer border ${
              isCopied
                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                : 'bg-surface hover:bg-surface-active text-zinc-300 hover:text-white border-border-subtle'
            }`}
            title="Copy to clipboard (auto-wipes in 30s)"
          >
            {isCopied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400 stroke-[2.5]" />
                <span>Copied ({copyTimeLeft}s)</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy</span>
              </>
            )}
          </button>

          {/* Delete Button */}
          {isDeleting ? (
            <div className="flex items-center gap-1 bg-red-950/80 p-0.5 rounded-md border border-red-800">
              <button
                onClick={handleDeleteConfirm}
                className="px-2 py-0.5 text-[10px] font-mono font-bold text-red-200 hover:text-white cursor-pointer"
                title="Confirm deletion"
              >
                Confirm
              </button>
              <button
                onClick={() => setIsDeleting(false)}
                className="px-1.5 py-0.5 text-[10px] font-mono text-zinc-400 hover:text-zinc-200 cursor-pointer"
                title="Cancel deletion"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setIsDeleting(true)}
              className="p-1.5 rounded-md text-zinc-400 hover:text-rose-400 hover:bg-rose-950/30 border border-transparent hover:border-rose-900/40 transition-colors cursor-pointer"
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
