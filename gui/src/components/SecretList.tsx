import React from 'react';
import { Plus, KeyRound } from 'lucide-react';
import { SecretItem } from '../types';
import { SecretCard } from './SecretCard';

interface SecretListProps {
  secrets: SecretItem[];
  onRevealToggle: (key: string, currentRevealed: boolean) => Promise<string | void>;
  onDelete: (key: string) => Promise<void>;
  onAddSecretClick: () => void;
  onCopySuccess: (key: string) => void;
  searchQuery?: string;
}

export const SecretList: React.FC<SecretListProps> = ({
  secrets,
  onRevealToggle,
  onDelete,
  onAddSecretClick,
  onCopySuccess,
  searchQuery = '',
}) => {
  if (secrets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center bg-surface/50 rounded-lg border border-dashed border-subpixel select-none">
        <div className="w-10 h-10 rounded-full bg-inset flex items-center justify-center mb-3 border border-subpixel">
          <KeyRound className="w-5 h-5 text-gray-400" />
        </div>
        <h3 className="font-mono text-sm font-semibold text-gray-300">
          {searchQuery ? 'NO MATCHING SECRETS FOUND' : 'NO SECRETS STORED IN THIS SCOPE'}
        </h3>
        <p className="text-xs text-gray-400 max-w-xs mt-1 font-mono">
          {searchQuery
            ? `No credentials matching "${searchQuery}". Press Esc to clear filter.`
            : 'Add credentials to your OS hardware store or launch a CLI injector session.'}
        </p>
        <button
          onClick={onAddSecretClick}
          className="mt-4 flex items-center gap-1.5 px-3 py-1.5 rounded bg-radar-core hover:bg-radar-glow text-black font-bold text-xs font-mono transition-all shadow-radar-glow-sm cursor-pointer active:scale-95"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>STORE NEW SECRET (⌘N)</span>
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {secrets.map((secret) => (
        <SecretCard
          key={`${secret.scope}-${secret.key}`}
          secret={secret}
          onRevealToggle={onRevealToggle}
          onDelete={onDelete}
          onCopySuccess={onCopySuccess}
        />
      ))}
    </div>
  );
};
