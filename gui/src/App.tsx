import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Plus } from 'lucide-react';
import { SecretItem, ScopeFilter, ProxyStatus, SecurityStatus, JitRequest, SecretScope } from './types';
import { api } from './api';
import { Sidebar } from './components/Sidebar';
import { SearchBar } from './components/SearchBar';
import { SecretList } from './components/SecretList';
import { AddSecretModal } from './components/AddSecretModal';
import { JitApprovalModal } from './components/JitApprovalModal';

export const App: React.FC = () => {
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentScope, setCurrentScope] = useState<ScopeFilter>('all');
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
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

  // Global Keyboard Shortcuts (⌘N for new)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        setIsAddModalOpen(true);
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
  };

  // Distinct project list derived from stored secrets
  const projectList = useMemo(() => {
    const set = new Set<string>();
    secrets.forEach((s) => {
      if (s.scope === 'project' && s.project) {
        set.add(s.project);
      }
    });
    if (set.size === 0) {
      set.add('cloak-core');
    }
    return Array.from(set);
  }, [secrets]);

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
    return cats.map((c) => ({
      ...c,
      count:
        c.id === 'all'
          ? secrets.length
          : secrets.filter((s) => s.category === c.id).length,
    }));
  }, [secrets]);

  // Filtered Secrets list
  const filteredSecrets = useMemo(() => {
    return secrets.filter((s) => {
      // Scope filter
      if (currentScope === 'global' && s.scope !== 'global') return false;
      if (currentScope === 'project') {
        if (s.scope !== 'project') return false;
        if (selectedProject && s.project !== selectedProject) return false;
      }

      // Category filter
      if (activeCategory !== 'all' && s.category !== activeCategory) return false;

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesKey = s.key.toLowerCase().includes(q);
        const matchesProject = s.project?.toLowerCase().includes(q);
        const matchesCategory = s.category.toLowerCase().includes(q);
        return matchesKey || matchesProject || matchesCategory;
      }
      return true;
    });
  }, [secrets, currentScope, selectedProject, activeCategory, searchQuery]);

  const activeVaultTitle = useMemo(() => {
    if (currentScope === 'global') return 'Global Secrets (macOS Keychain)';
    if (currentScope === 'project') {
      return selectedProject ? `Project: ${selectedProject}` : 'All Projects';
    }
    return 'All Secrets';
  }, [currentScope, selectedProject]);

  return (
    <div className="h-screen w-full flex bg-canvas text-zinc-100 overflow-hidden font-sans select-none">
      {/* Sidebar Navigation */}
      <Sidebar
        currentScope={currentScope}
        onSelectScope={(scope) => {
          setCurrentScope(scope);
          if (scope !== 'project') {
            setSelectedProject(null);
          } else if (!selectedProject && projectList.length > 0) {
            setSelectedProject(projectList[0]);
          }
        }}
        selectedProject={selectedProject}
        onSelectProject={(proj) => {
          setCurrentScope('project');
          setSelectedProject(proj);
        }}
        projectList={projectList}
        counts={counts}
        proxyStatus={proxyStatus}
        onToggleProxy={handleToggleProxy}
        securityStatus={securityStatus}
        onToggleLock={handleToggleLock}
        onSimulateJit={handleSimulateJit}
        pendingJitCount={pendingJit ? 1 : 0}
      />

      {/* Main Vault Content Area */}
      <main className="flex-1 flex flex-col min-w-0 bg-canvas overflow-hidden">
        {/* Top Action Bar */}
        <header className="px-6 py-4 border-b border-border-subtle bg-surface/40 flex items-center justify-between gap-4">
          <div className="flex-1 min-w-0">
            <SearchBar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              activeCategory={activeCategory}
              onCategoryChange={setActiveCategory}
              categories={categories}
            />
          </div>

          <button
            onClick={() => setIsAddModalOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white hover:bg-zinc-200 text-zinc-950 font-semibold text-xs transition-colors cursor-pointer flex-shrink-0 shadow-sm"
            title="Store new secret in hardware vault (⌘N)"
          >
            <Plus className="w-4 h-4" />
            <span>New Secret</span>
          </button>
        </header>

        {/* Vault Title and Details */}
        <div className="px-6 pt-4 pb-2 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100 tracking-tight">
              {activeVaultTitle}
            </h2>
            <p className="text-xs text-zinc-400">
              {filteredSecrets.length} {filteredSecrets.length === 1 ? 'secret' : 'secrets'} stored
            </p>
          </div>
        </div>

        {/* Secrets List Container */}
        <div className="flex-1 overflow-y-auto px-6 py-3">
          {loading ? (
            <div className="flex items-center justify-center p-12 text-zinc-500 font-mono text-xs">
              Loading secure vault...
            </div>
          ) : (
            <SecretList
              secrets={filteredSecrets}
              onRevealToggle={handleRevealToggle}
              onDelete={handleDeleteSecret}
              onAddSecretClick={() => setIsAddModalOpen(true)}
              onCopySuccess={(key) => showToast(`Copied ${key} to clipboard`)}
              searchQuery={searchQuery}
            />
          )}
        </div>
      </main>

      {/* Add Secret Modal */}
      <AddSecretModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSave={handleSaveSecret}
        defaultScope={currentScope === 'project' ? 'project' : 'global'}
        currentProjectName={selectedProject || 'cloak-core'}
      />

      {/* JIT Security Approval Modal */}
      <JitApprovalModal
        request={pendingJit}
        onRespond={handleRespondJit}
        onClose={() => setPendingJit(null)}
      />

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-4 right-4 z-50 px-3.5 py-2 rounded-lg bg-zinc-800 text-zinc-100 text-xs font-mono border border-border-subtle shadow-lg transition-all animate-fadeIn">
          {toastMessage}
        </div>
      )}
    </div>
  );
};
