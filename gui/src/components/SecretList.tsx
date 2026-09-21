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
      <div className="flex flex-col items-center justify-center p-12 text-center bg-surface/40 rounded-xl border border-dashed border-border-subtle select-none">
        <div className="w-10 h-10 rounded-full bg-surface-active flex items-center justify-center mb-3 border border-border-subtle text-zinc-400">
          <KeyRound className="w-4 h-4" />
        </div>
        <h3 className="text-sm font-semibold text-zinc-200">
          {searchQuery ? 'No matching secrets found' : 'No secrets stored in this scope'}
        </h3>
        <p className="text-xs text-zinc-400 max-w-sm mt-1">
          {searchQuery
            ? `No credentials match "${searchQuery}". Clear your search query to see all items.`
            : 'Store API keys, tokens, or environment credentials directly into your OS hardware keystore.'}
        </p>
        <button
          onClick={onAddSecretClick}
          className="mt-4 flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white hover:bg-zinc-200 text-zinc-950 font-semibold text-xs transition-colors cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Secret (⌘N)</span>
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
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
