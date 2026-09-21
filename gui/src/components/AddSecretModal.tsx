import React, { useState, useEffect, useRef } from 'react';
import { X, Key, Lock, Globe, FolderGit2, ShieldCheck, Eye, EyeOff } from 'lucide-react';
import { SecretScope } from '../types';

interface AddSecretModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (key: string, value: string, scope: SecretScope, project?: string) => Promise<void>;
  defaultScope?: SecretScope;
  currentProjectName?: string;
}

export const AddSecretModal: React.FC<AddSecretModalProps> = ({
  isOpen,
  onClose,
  onSave,
  defaultScope = 'global',
  currentProjectName = 'cloak-core',
}) => {
  const [key, setKey] = useState('');
  const [value, setValue] = useState('');
  const [scope, setScope] = useState<SecretScope>(defaultScope);
  const [project, setProject] = useState(currentProjectName);
  const [showValue, setShowValue] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const keyInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setKey('');
      setValue('');
      setScope(defaultScope);
      setProject(currentProjectName);
      setErrorMessage(null);
      setTimeout(() => {
        keyInputRef.current?.focus();
      }, 50);
    }
  }, [isOpen, defaultScope, currentProjectName]);

  // Keyboard navigation: Esc to close, Enter to submit (unless in textarea)
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!key.trim()) {
      setErrorMessage('Secret key name is required (e.g. OPENAI_API_KEY)');
      return;
    }
    if (!value.trim()) {
      setErrorMessage('Secret value is required');
      return;
    }

    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      await onSave(
        key.trim().toUpperCase(),
        value.trim(),
        scope,
        scope === 'project' ? project.trim() : undefined
      );
      onClose();
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to save secret to hardware store');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn select-none">
      <div className="relative w-full max-w-md bg-surface rounded-lg border border-radar-border shadow-2xl overflow-hidden">
        {/* Top Accent Strip */}
        <div className="h-1 bg-gradient-to-r from-radar-border via-radar-core to-radar-glow" />

        {/* Modal Header */}
        <div className="flex items-center justify-between px-4 py-3 bg-inset/60 border-b border-subpixel">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-radar-core" />
            <span className="font-mono text-xs font-bold tracking-wider text-gray-100 uppercase">
              [ STORE HARDWARE CREDENTIAL ]
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-elevated transition-colors cursor-pointer"
            title="Cancel (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {errorMessage && (
            <div className="px-3 py-2 rounded bg-red-950/40 border border-red-800/80 text-red-200 font-mono text-xs">
              ⚠️ {errorMessage}
            </div>
          )}

          {/* Scope Selector */}
          <div>
            <label className="block font-mono text-[10px] uppercase font-bold text-gray-400 mb-1.5">
              TARGET SCOPE
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setScope('global')}
                className={`flex items-center justify-center gap-2 p-2 rounded text-xs font-mono border transition-all cursor-pointer ${
                  scope === 'global'
                    ? 'bg-radar-dim text-radar-glow border-radar-border font-bold shadow-radar-glow-sm'
                    : 'bg-inset text-gray-400 hover:text-gray-200 border-subpixel hover:bg-elevated'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>🌐 GLOBAL (Keychain)</span>
              </button>

              <button
                type="button"
                onClick={() => setScope('project')}
                className={`flex items-center justify-center gap-2 p-2 rounded text-xs font-mono border transition-all cursor-pointer ${
                  scope === 'project'
                    ? 'bg-radar-dim text-radar-glow border-radar-border font-bold shadow-radar-glow-sm'
                    : 'bg-inset text-gray-400 hover:text-gray-200 border-subpixel hover:bg-elevated'
                }`}
              >
                <FolderGit2 className="w-3.5 h-3.5" />
                <span>📁 PROJECT ONLY</span>
              </button>
            </div>
          </div>

          {/* Project Namespace (Conditional) */}
          {scope === 'project' && (
            <div className="animate-fadeIn">
              <label className="block font-mono text-[10px] uppercase font-bold text-gray-400 mb-1">
                PROJECT IDENTIFIER / NAMESPACE
              </label>
              <input
                type="text"
                value={project}
                onChange={(e) => setProject(e.target.value)}
                placeholder="e.g. cloak-core, payment-api"
                className="w-full px-3 py-2 bg-inset text-gray-100 font-mono text-xs rounded border border-subpixel focus:border-radar-core focus:ring-1 focus:ring-radar-core/40 focus:outline-none"
              />
            </div>
          )}

          {/* Secret Key Input */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="font-mono text-[10px] uppercase font-bold text-gray-400">
                KEY IDENTIFIER (ENV VAR)
              </label>
              <span className="text-[10px] font-mono text-gray-400">UPPERCASE_SNAKE</span>
            </div>
            <div className="relative flex items-center">
              <input
                ref={keyInputRef}
                type="text"
                value={key}
                onChange={(e) => setKey(e.target.value.toUpperCase().replace(/\s+/g, '_'))}
                placeholder="OPENAI_API_KEY"
                className="w-full px-3 py-2 bg-inset text-radar-glow font-mono text-xs rounded border border-subpixel focus:border-radar-core focus:ring-1 focus:ring-radar-core/40 focus:outline-none"
              />
            </div>
          </div>

          {/* Secret Value Input */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="font-mono text-[10px] uppercase font-bold text-gray-400">
                SECRET VALUE
              </label>
              <span className="text-[10px] font-mono text-gray-400">ENCRYPTED AT REST</span>
            </div>
            <div className="relative flex items-center">
              <input
                type={showValue ? 'text' : 'password'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="sk-proj-..."
                className="w-full pl-3 pr-10 py-2 bg-inset text-gray-100 font-mono text-xs rounded border border-subpixel focus:border-radar-core focus:ring-1 focus:ring-radar-core/40 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowValue(!showValue)}
                className="absolute right-2 p-1 text-gray-400 hover:text-gray-200 cursor-pointer"
                title={showValue ? 'Hide value' : 'Show value'}
              >
                {showValue ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Security Notice */}
          <div className="flex items-center gap-2 p-2 rounded bg-inset/40 border border-subpixel text-[10px] font-mono text-gray-400">
            <ShieldCheck className="w-3.5 h-3.5 text-radar-core flex-shrink-0" />
            <span>Encrypted directly into Apple Keychain / Secure Enclave hardware block.</span>
          </div>

          {/* Modal Actions */}
          <div className="flex items-center justify-end gap-2 pt-2 border-t border-subpixel">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded font-mono text-xs text-gray-400 hover:text-gray-200 hover:bg-elevated transition-colors cursor-pointer"
            >
              CANCEL (ESC)
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded font-mono text-xs font-bold bg-radar-core hover:bg-radar-glow text-black transition-all shadow-radar-glow-sm active:scale-95 cursor-pointer disabled:opacity-50"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{isSubmitting ? 'ENCRYPTING...' : 'STORE SECRET (ENTER)'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
