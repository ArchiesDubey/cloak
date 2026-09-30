import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Copy, Check, Trash2, ShieldCheck, Database, KeyRound, Lock, RotateCw, History } from 'lucide-react';
import { SecretItem } from '../types';
import { api } from '../api';

interface SecretCardProps {
  secret: SecretItem;
  onRevealToggle: (secret: SecretItem, currentRevealed: boolean) => Promise<string | void>;
  onDelete: (secret: SecretItem) => Promise<void>;
  onCopySuccess: (key: string) => void;
  onRotate?: (secret: SecretItem, newValue: string) => Promise<void>;
  onRollback?: (secret: SecretItem) => Promise<void>;
}

export const SecretCard: React.FC<SecretCardProps> = ({
  secret,
  onRevealToggle,
  onDelete,
  onCopySuccess,
  onRotate,
  onRollback,
}) => {
  const [isRevealed, setIsRevealed] = useState(false);
  const [revealedValue, setRevealedValue] = useState<string | null>(null);
  const [isLoadingReveal, setIsLoadingReveal] = useState(false);
  const [isCopied, setIsCopied] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [copyTimeLeft, setCopyTimeLeft] = useState<number>(0);

  // Rotation state
  const [isRotating, setIsRotating] = useState(false);
  const [rotateValue, setRotateValue] = useState('');
  const [isLoadingRotate, setIsLoadingRotate] = useState(false);
  const [isRollingBack, setIsRollingBack] = useState(false);
  const [isLoadingRollback, setIsLoadingRollback] = useState(false);

  // 30-second clipboard countdown with real auto-wipe
  useEffect(() => {
    let timer: ReturnType<typeof setInterval>;
    if (isCopied) {
      setCopyTimeLeft(30);
      timer = setInterval(() => {
        setCopyTimeLeft((prev) => {
          if (prev <= 1) {
            setIsCopied(false);
            clearInterval(timer);
            navigator.clipboard?.writeText('').catch(() => {});
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
      const val = await onRevealToggle(secret, isRevealed);
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
      const scopeParam = secret.scope === 'project' ? (secret.project || 'cloak-core') : 'global';
      await api.copySecretSecure(secret.key, scopeParam);
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
    await onDelete(secret);
  };

  const handleRotateSubmit = async () => {
    if (!rotateValue.trim()) return;
    try {
      setIsLoadingRotate(true);
      if (onRotate) {
        await onRotate(secret, rotateValue.trim());
      } else {
        const scopeParam = secret.scope === 'project' ? (secret.project || 'cloak-core') : 'global';
        await api.rotateSecret(secret.key, rotateValue.trim(), scopeParam);
      }
      setIsRotating(false);
      setRotateValue('');
    } catch (err) {
      console.error('Failed to rotate secret', err);
    } finally {
      setIsLoadingRotate(false);
    }
  };

  const handleRollbackConfirm = async () => {
    try {
      setIsLoadingRollback(true);
      if (onRollback) {
        await onRollback(secret);
      } else {
        const scopeParam = secret.scope === 'project' ? (secret.project || 'cloak-core') : 'global';
        await api.rollbackSecret(secret.key, scopeParam);
      }
      setIsRollingBack(false);
    } catch (err) {
      console.error('Failed to rollback secret', err);
    } finally {
      setIsLoadingRollback(false);
    }
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

  const renderRotationBadge = () => {
    const ts = secret.lastRotatedAt || secret.createdAt;
    if (!ts) return null;
    const now = Math.floor(Date.now() / 1000);
    const diff = Math.max(0, now - ts);
    const days = Math.floor(diff / 86400);
    const isStale = days >= 90;

    let ageStr = '';
    if (days === 0) {
      const hours = Math.floor(diff / 3600);
      ageStr = hours === 0 ? 'just now' : `${hours}h ago`;
    } else {
      ageStr = `${days}d ago`;
    }

    if (isStale) {
      return (
        <span
          className="inline-flex items-center gap-1 text-[10px] text-burnrate-critical bg-[#FF3F00]/10 px-1.5 py-0.5 rounded border border-burnrate-critical/30 font-mono font-medium"
          title={`Secret has not been rotated in ${days} days (>90d threshold)`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-burnrate-critical animate-pulse" />
          STALE ({ageStr})
        </span>
      );
    }

    return (
      <span
        className="hidden sm:inline-flex items-center gap-1 text-[10px] text-[#808080] bg-surface-active px-1.5 py-0.5 rounded border border-border-subtle font-mono"
        title={secret.lastRotatedAt ? `Last rotated: ${ageStr}` : `Created: ${ageStr}`}
      >
        {secret.lastRotatedAt ? `Rotated ${ageStr}` : `Added ${ageStr}`}
      </span>
    );
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
          {renderRotationBadge()}

          {secret.hasRollback && (
            <span
              className="hidden sm:inline-flex items-center gap-1 text-[10px] text-burnrate-watch bg-[#FF9900]/10 px-1.5 py-0.5 rounded border border-[#FF9900]/30 font-mono font-medium"
              title="Rollback backup version available"
            >
              Rollback Ready
            </span>
          )}

          {secret.scope === 'project' ? (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-active text-zinc-300 border border-border-subtle">
              {secret.project || 'project'}
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-active text-zinc-300 border border-border-subtle font-medium">
              GLOBAL
            </span>
          )}

          {secret.hardwareProtected ? (
            <span
              className="hidden sm:inline-flex items-center gap-1 text-[10px] text-burnrate-watch bg-[#FF9900]/10 px-1.5 py-0.5 rounded border border-[#FF9900]/30 font-mono font-medium"
              title="Hardware ACL: Protected by Secure Enclave / Biometrics"
            >
              <ShieldCheck className="w-3 h-3 text-burnrate-watch" />
              Touch ID Enclave
            </span>
          ) : (
            <span
              className="hidden sm:inline-flex items-center gap-1 text-[10px] text-[#808080] bg-surface-active px-1.5 py-0.5 rounded border border-border-subtle font-mono"
              title="Stored in standard OS Keychain"
            >
              <ShieldCheck className="w-3 h-3 text-burnrate-ample" />
              Standard Keyring
            </span>
          )}
        </div>
      </div>

      {/* Value Row & Quick Actions */}
      <div className="flex items-center justify-between gap-3 pt-2.5 border-t border-border-subtle">
        {/* Value Display */}
        <div className="min-w-0 flex-1 font-mono text-xs text-[#808080] select-text truncate">
          {isLoadingReveal ? (
            <span className="text-[#6E6E73] animate-pulse">Decrypting with OS Keychain...</span>
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

          {/* Rotate Button */}
          <button
            onClick={() => {
              setIsRotating(!isRotating);
              setIsRollingBack(false);
            }}
            className={`p-1.5 rounded-md transition-all duration-150 ease-spring cursor-pointer border ${
              isRotating
                ? 'bg-surface-active text-burnrate-ample border-burnrate-ample/40'
                : 'bg-surface hover:bg-surface-hover text-[#808080] hover:text-burnrate-ample border-border-subtle'
            }`}
            title="Rotate secret value (archives current version for rollback)"
          >
            <RotateCw className="w-3.5 h-3.5" />
          </button>

          {/* Rollback Button (if available) */}
          {secret.hasRollback && (
            isRollingBack ? (
              <div className="flex items-center gap-1 bg-[#FF9900]/10 p-0.5 rounded-md border border-burnrate-watch/50">
                <button
                  onClick={handleRollbackConfirm}
                  disabled={isLoadingRollback}
                  className="px-2 py-0.5 text-[10px] font-mono font-bold text-burnrate-watch hover:text-white cursor-pointer"
                  title="Confirm rollback to previous secret value"
                >
                  {isLoadingRollback ? 'Rolling back...' : 'Confirm'}
                </button>
                <button
                  onClick={() => setIsRollingBack(false)}
                  className="px-1.5 py-0.5 text-[10px] font-mono text-[#808080] hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <button
                onClick={() => {
                  setIsRollingBack(true);
                  setIsRotating(false);
                }}
                className="p-1.5 rounded-md text-[#808080] hover:text-burnrate-watch hover:bg-[#FF9900]/10 border border-transparent hover:border-burnrate-watch/30 transition-colors cursor-pointer"
                title="Rollback to previously stored secret version"
              >
                <History className="w-3.5 h-3.5" />
              </button>
            )
          )}

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

      {/* Inline Rotate Form */}
      {isRotating && (
        <div className="mt-2.5 pt-2.5 border-t border-border-subtle flex items-center gap-2">
          <input
            type="password"
            value={rotateValue}
            onChange={(e) => setRotateValue(e.target.value)}
            placeholder="Enter new secret value to rotate..."
            className="flex-1 bg-surface-active border border-border-subtle rounded px-2.5 py-1 text-xs font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-burnrate-ample"
            autoFocus
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleRotateSubmit();
              if (e.key === 'Escape') setIsRotating(false);
            }}
          />
          <button
            onClick={handleRotateSubmit}
            disabled={isLoadingRotate || !rotateValue.trim()}
            className="px-2.5 py-1 text-xs font-mono font-semibold bg-burnrate-ample/15 text-burnrate-ample border border-burnrate-ample/40 rounded hover:bg-burnrate-ample/25 cursor-pointer disabled:opacity-40"
          >
            {isLoadingRotate ? 'Rotating...' : 'Rotate'}
          </button>
          <button
            onClick={() => {
              setIsRotating(false);
              setRotateValue('');
            }}
            className="px-2 py-1 text-xs font-mono text-[#808080] hover:text-white cursor-pointer"
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
};
