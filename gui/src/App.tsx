import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Plus } from 'lucide-react';
import { SecretItem, ScopeFilter, ProxyStatus, SecurityStatus, JitRequest, SecretScope } from './types';
import { api } from './api';
import { Header } from './components/Header';
import { ScopeTabs } from './components/ScopeTabs';
import { SearchBar } from './components/SearchBar';
import { SecretList } from './components/SecretList';
import { AddSecretModal } from './components/AddSecretModal';
import { JitApprovalModal } from './components/JitApprovalModal';
import { TelemetryPanel } from './components/TelemetryPanel';

export const App: React.FC = () => {
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [isCompact, setIsCompact] = useState(false);
  const [currentScope, setCurrentScope] = useState<ScopeFilter>('global');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState('all');

  const [proxyStatus, setProxyStatus] = useState<ProxyStatus>({
    running: true,
    port: 4141,
    interceptCount: 23,
  });

  const [securityStatus, setSecurityStatus] = useState<SecurityStatus>({
    hardwareBackend: 'Apple Keychain (Secure Enclave)',
    isUnlocked: true,
    biometricType: 'Touch ID',
    memoryLockActive: true,
    coreDumpsDisabled: true,
  });

  const [pendingJit, setPendingJit] = useState<JitRequest | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isJitModalOpen, setIsJitModalOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Load initial secrets & statuses
  const refreshData = useCallback(async () => {
    try {
      setLoading(true);
      const [items, pStatus, sStatus, jit] = await Promise.all([
        api.listSecrets(),
        api.getProxyStatus(),
        api.getSecurityStatus(),
        api.getPendingJitRequest(),
      ]);
      setSecrets(items);
      setProxyStatus(pStatus);
      setSecurityStatus(sStatus);
      if (jit) {
        setPendingJit(jit);
        setIsJitModalOpen(true);
      }
    } catch (err) {
      console.error('Failed to load Cloak vault data', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  // Global Keyboard Shortcuts (⌘N for new, ⌘E for compact toggle)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        setIsAddModalOpen(true);
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'e') {
        e.preventDefault();
        setIsCompact((prev) => !prev);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Handlers
  const handleRevealToggle = async (key: string, currentRevealed: boolean): Promise<string | void> => {
    if (!currentRevealed) {
      const full = await api.getSecret(key, true);
      return full;
    }
  };

  const handleDeleteSecret = async (key: string) => {
    await api.deleteSecret(key);
    setSecrets((prev) => prev.filter((s) => s.key !== key));
    showToast(`Deleted ${key} from hardware store`);
  };

  const handleSaveSecret = async (
    key: string,
    value: string,
    scope: SecretScope,
    project?: string
  ) => {
    const created = await api.setSecret(key, value, scope, project);
    setSecrets((prev) => {
      const existing = prev.findIndex((s) => s.key === key);
      if (existing >= 0) {
        const copy = [...prev];
        copy[existing] = created;
        return copy;
      }
      return [created, ...prev];
    });
    showToast(`Secured ${key} in hardware enclave`);
  };

  const handleToggleProxy = async () => {
    const next = await api.toggleProxy();
    setProxyStatus(next);
    showToast(`Proxy ${next.running ? 'enabled on port 4141' : 'stopped'}`);
  };

  const handleToggleLock = async () => {
    const unlocked = await api.toggleVaultLock();
    setSecurityStatus((prev) => ({ ...prev, isUnlocked: unlocked }));
    showToast(unlocked ? 'Hardware vault unlocked with Touch ID' : 'Hardware vault locked');
  };

  const handleRespondJit = async (requestId: string, action: 'deny' | 'once' | 'always') => {
    await api.respondJit(requestId, action);
    setPendingJit(null);
    setIsJitModalOpen(false);
    const refreshedProxy = await api.getProxyStatus();
    setProxyStatus(refreshedProxy);
    showToast(`JIT Request: ${action.toUpperCase()}`);
  };

  const handleSimulateJit = () => {
    const sampleReq: JitRequest = {
      id: `jit-req-${Math.floor(Math.random() * 9000 + 1000)}`,
      agent: 'claude-code',
      key: 'OPENAI_API_KEY',
      timestamp: 'Just now',
      targetEndpoint: 'http://127.0.0.1:4141/v1/chat/completions',
      processPid: Math.floor(Math.random() * 50000 + 30000),
      status: 'pending',
    };
    setPendingJit(sampleReq);
    setIsJitModalOpen(true);
  };

  // Scope Counts
  const counts = useMemo(() => {
    return {
      all: secrets.length,
      global: secrets.filter((s) => s.scope === 'global').length,
      project: secrets.filter((s) => s.scope === 'project').length,
    };
  }, [secrets]);

  // Categories with counts
  const categories = useMemo(() => {
    const cats = [
      { id: 'all', label: 'All' },
      { id: 'api-key', label: 'API Keys' },
      { id: 'database', label: 'Database' },
      { id: 'token', label: 'Tokens' },
    ];
    return cats.map((cat) => {
      if (cat.id === 'all') return { ...cat, count: secrets.length };
      return {
        ...cat,
        count: secrets.filter((s) => s.category === cat.id).length,
      };
    });
  }, [secrets]);

  // Filtered Secrets
  const filteredSecrets = useMemo(() => {
    return secrets.filter((item) => {
      // Scope filter
      if (currentScope !== 'all' && item.scope !== currentScope) {
        return false;
      }
      // Category filter
      if (activeCategory !== 'all' && item.category !== activeCategory) {
        return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchesKey = item.key.toLowerCase().includes(query);
        const matchesProject = item.project?.toLowerCase().includes(query) ?? false;
        return matchesKey || matchesProject;
      }
      return true;
    });
  }, [secrets, currentScope, activeCategory, searchQuery]);

  return (
    <div
      className={`h-screen flex flex-col bg-canvas text-gray-200 overflow-hidden font-sans transition-all duration-200 ${
        isCompact ? 'max-w-[420px] mx-auto border-x border-subpixel shadow-2xl' : 'w-full'
      }`}
    >
      {/* Header */}
      <Header
        isCompact={isCompact}
        onToggleCompact={() => setIsCompact(!isCompact)}
        proxyStatus={proxyStatus}
        onToggleProxy={handleToggleProxy}
        securityStatus={securityStatus}
        onToggleLock={handleToggleLock}
        pendingJitCount={pendingJit ? 1 : 0}
        onOpenJitModal={() => setIsJitModalOpen(true)}
      />

      {/* Main Container */}
      <div className="flex-1 flex overflow-hidden p-3 gap-3">
        {/* Secrets Column */}
        <main className="flex-1 flex flex-col gap-3 min-w-0 overflow-hidden">
          {/* Controls row: Scope Tabs & Add Button */}
          <div className="flex items-center gap-2">
            <div className="flex-1 min-w-0">
              <ScopeTabs
                currentScope={currentScope}
                onSelectScope={setCurrentScope}
                counts={counts}
                currentProjectName="cloak-core"
              />
            </div>
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded bg-radar-core hover:bg-radar-glow text-black font-mono text-xs font-bold transition-all shadow-radar-glow-sm cursor-pointer active:scale-95 flex-shrink-0"
              title="Store new secret in hardware vault (⌘N)"
            >
              <Plus className="w-4 h-4 stroke-[2.5]" />
              <span className="hidden sm:inline">STORE</span>
            </button>
          </div>

          {/* Search and Tags */}
          <SearchBar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            activeCategory={activeCategory}
            onCategoryChange={setActiveCategory}
            categories={categories}
          />

          {/* Secret Cards Scrollable Area */}
          <div className="flex-1 overflow-y-auto pr-0.5 space-y-2">
            {loading ? (
              <div className="flex items-center justify-center p-12 text-gray-400 font-mono text-xs">
                <span className="animate-pulse">[ACCESSING OS HARDWARE KEYRING...]</span>
              </div>
            ) : (
              <SecretList
                secrets={filteredSecrets}
                onRevealToggle={handleRevealToggle}
                onDelete={handleDeleteSecret}
                onAddSecretClick={() => setIsAddModalOpen(true)}
                onCopySuccess={(key) => showToast(`Copied ${key} &bull; 30s auto-purge active`)}
                searchQuery={searchQuery}
              />
            )}
          </div>

          {/* Quick HUD Footer */}
          <footer className="pt-2 border-t border-subpixel flex items-center justify-between text-[10px] font-mono text-gray-400 select-none">
            <div className="flex items-center gap-3">
              <span>⌘K Search</span>
              <span>⌘N Store</span>
              <span>⌘E HUD/Wide</span>
            </div>
            <div className="flex items-center gap-1 text-radar-glow">
              <div className="w-1.5 h-1.5 rounded-full bg-radar-core" />
              <span>0-PLAINTEXT DISK</span>
            </div>
          </footer>
        </main>

        {/* Telemetry Sidebar in Expanded Desktop Mode */}
        {!isCompact && (
          <TelemetryPanel
            proxyStatus={proxyStatus}
            securityStatus={securityStatus}
            totalSecretsCount={secrets.length}
            onSimulateJit={handleSimulateJit}
          />
        )}
      </div>

      {/* Floating Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 px-3 py-1.5 rounded bg-surface border border-radar-border shadow-radar-glow-sm text-radar-glow text-xs font-mono animate-fadeIn flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-radar-core" />
          <span dangerouslySetInnerHTML={{ __html: toastMessage }} />
        </div>
      )}

      {/* Modals */}
      <AddSecretModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSave={handleSaveSecret}
        defaultScope={currentScope === 'project' ? 'project' : 'global'}
        currentProjectName="cloak-core"
      />

      <JitApprovalModal
        request={isJitModalOpen ? pendingJit : null}
        onRespond={handleRespondJit}
        onClose={() => setIsJitModalOpen(false)}
      />
    </div>
  );
};
