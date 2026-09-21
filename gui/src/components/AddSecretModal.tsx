import React, { useState, useEffect, useRef } from 'react';
import { X, KeyRound, Globe, FolderGit2, ShieldCheck, Eye, EyeOff } from 'lucide-react';
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

  // Keyboard navigation: Esc to close
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm select-none">
      <div className="relative w-full max-w-md bg-surface rounded-xl border border-border-subtle shadow-modal overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-subtle">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-surface-active flex items-center justify-center border border-border-subtle">
              <KeyRound className="w-3.5 h-3.5 text-zinc-300" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-zinc-100">
                Store Secret
              </h3>
              <p className="text-xs text-zinc-400">
                Encrypted directly into hardware keystore
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-zinc-400 hover:text-zinc-200 hover:bg-surface-hover transition-colors cursor-pointer"
            title="Close (Esc)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {errorMessage && (
            <div className="px-3 py-2 rounded-lg bg-red-950/40 border border-red-800/80 text-red-200 text-xs font-mono">
              ⚠️ {errorMessage}
            </div>
          )}

          {/* Scope Selector */}
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1.5">
              Vault Scope
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setScope('global')}
                className={`flex items-center justify-center gap-2 p-2 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
                  scope === 'global'
                    ? 'bg-zinc-800 text-white border-zinc-600 shadow-sm'
                    : 'bg-surface text-zinc-400 hover:text-zinc-200 border-border-subtle hover:bg-surface-hover'
                }`}
              >
                <Globe className="w-3.5 h-3.5" />
                <span>Global (Keychain)</span>
              </button>

              <button
                type="button"
                onClick={() => setScope('project')}
                className={`flex items-center justify-center gap-2 p-2 rounded-lg text-xs font-medium border transition-colors cursor-pointer ${
                  scope === 'project'
                    ? 'bg-zinc-800 text-white border-zinc-600 shadow-sm'
                    : 'bg-surface text-zinc-400 hover:text-zinc-200 border-border-subtle hover:bg-surface-hover'
                }`}
              >
                <FolderGit2 className="w-3.5 h-3.5" />
                <span>Project Only</span>
              </button>
            </div>
          </div>

          {/* Project Namespace (Conditional) */}
          {scope === 'project' && (
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Project Name
              </label>
              <input
                type="text"
                value={project}
                onChange={(e) => setProject(e.target.value)}
                placeholder="e.g. cloak-core, web-app"
                className="w-full px-3 py-2 bg-surface-active text-zinc-100 font-mono text-xs rounded-lg border border-border-subtle focus:border-zinc-500 focus:outline-none"
              />
            </div>
          )}

          {/* Secret Key Input */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-zinc-300">
                Key Identifier
              </label>
              <span className="text-[10px] text-zinc-500 font-mono">ENV_VAR_NAME</span>
            </div>
            <input
              ref={keyInputRef}
              type="text"
              value={key}
              onChange={(e) => setKey(e.target.value.toUpperCase().replace(/\s+/g, '_'))}
              placeholder="OPENAI_API_KEY"
              className="w-full px-3 py-2 bg-surface-active text-zinc-100 font-mono text-xs rounded-lg border border-border-subtle focus:border-zinc-500 focus:outline-none"
            />
          </div>

          {/* Secret Value Input */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-zinc-300">
                Secret Value
              </label>
              <span className="text-[10px] text-zinc-500">Hardware Encrypted</span>
            </div>
            <div className="relative flex items-center">
              <input
                type={showValue ? 'text' : 'password'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="sk-proj-..."
                className="w-full pl-3 pr-10 py-2 bg-surface-active text-zinc-100 font-mono text-xs rounded-lg border border-border-subtle focus:border-zinc-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowValue(!showValue)}
                className="absolute right-2 p-1 text-zinc-400 hover:text-zinc-200 cursor-pointer"
                title={showValue ? 'Hide value' : 'Show value'}
              >
                {showValue ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Hardware notice */}
          <div className="flex items-center gap-2 p-2.5 rounded-lg bg-surface-active/60 border border-border-subtle text-xs text-zinc-400">
            <ShieldCheck className="w-4 h-4 text-emerald-500 flex-shrink-0" />
            <span>Encrypted directly into Apple Keychain / Secure Enclave hardware block.</span>
          </div>

          {/* Modal Actions */}
          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-border-subtle">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 hover:bg-surface-hover transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-1.5 rounded-lg text-xs font-medium bg-white hover:bg-zinc-200 text-zinc-950 font-semibold transition-colors cursor-pointer disabled:opacity-50"
            >
              {isSubmitting ? 'Encrypting...' : 'Save Secret'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
