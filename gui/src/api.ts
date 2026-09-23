import { invoke } from '@tauri-apps/api/core';
import { SecretItem, ProxyStatus, SecurityStatus, JitRequest, SecretScope } from './types';
import { INITIAL_SECRETS, INITIAL_PROXY_STATUS, INITIAL_SECURITY_STATUS, INITIAL_PENDING_JIT } from './mockData';

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
    __TAURI__?: {
      core?: {
        invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
      };
      invoke?<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
    };
  }
}

const isTauri = (): boolean =>
  typeof window !== 'undefined' && (!!window.__TAURI_INTERNALS__ || !!window.__TAURI__);

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri()) {
    try {
      return await invoke<T>(cmd, args);
    } catch (err) {
      if (window.__TAURI__?.core?.invoke) {
        return await window.__TAURI__.core.invoke<T>(cmd, args);
      }
      throw err;
    }
  }
  throw new Error('Tauri invoke IPC is not available in standalone web browser');
}

// In-memory mock storage for browser testing / demo mode only
let mockSecrets: SecretItem[] = [...INITIAL_SECRETS];
let mockProxyStatus: ProxyStatus = { ...INITIAL_PROXY_STATUS };
let mockSecurityStatus: SecurityStatus = { ...INITIAL_SECURITY_STATUS };
let mockPendingJit: JitRequest | null = INITIAL_PENDING_JIT;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const api = {
  resetMockState: (): void => {
    mockSecrets = [...INITIAL_SECRETS];
    mockProxyStatus = { ...INITIAL_PROXY_STATUS };
    mockSecurityStatus = { ...INITIAL_SECURITY_STATUS };
    mockPendingJit = INITIAL_PENDING_JIT;
  },
  isDesktopApp: (): boolean => isTauri(),

  async listSecrets(scope?: string): Promise<SecretItem[]> {
    if (isTauri()) {
      // In desktop app, never fall back to mock data (A1 fix). Let errors surface!
      const dtos = await tauriInvoke<
        Array<{
          id: string;
          key: string;
          masked_value: string;
          scope: string;
          updated_at: string;
          hardware_protected?: boolean;
        }>
      >('list_secrets');

      const items: SecretItem[] = dtos.map((d) => ({
        key: d.key,
        maskedValue: d.masked_value,
        scope: (d.scope === 'global' ? 'global' : 'project') as SecretScope,
        project: d.scope !== 'global' ? d.scope : undefined,
        updatedAt: d.updated_at,
        category: d.key.toLowerCase().includes('db') || d.key.toLowerCase().includes('database')
          ? 'database'
          : d.key.toLowerCase().includes('token')
          ? 'token'
          : 'api-key',
        hardwareStored: true,
        hardwareProtected: d.hardware_protected ?? false,
      }));

      if (!scope || scope === 'all') {
        return items;
      }
      return items.filter((s) => s.scope === scope);
    }

    // Standalone browser fallback for Vite dev
    await delay(60);
    if (!scope || scope === 'all') {
      return [...mockSecrets];
    }
    return mockSecrets.filter((s) => s.scope === scope);
  },

  async getSecret(key: string, reveal: boolean, scope: string = 'global'): Promise<string> {
    if (isTauri()) {
      // Direct IPC call. If user cancels Touch ID or vault is locked, throws error to UI.
      return await tauriInvoke<string>('reveal_secret', { scope, key });
    }

    await delay(80);
    const item = mockSecrets.find((s) => s.key === key);
    if (!item) throw new Error(`Secret '${key}' not found in hardware store`);
    return reveal ? (item.fullValue || item.maskedValue) : item.maskedValue;
  },

  async setSecret(
    key: string,
    value: string,
    scope: SecretScope = 'global',
    project?: string,
    hardwareProtected: boolean = false
  ): Promise<SecretItem> {
    const scopeParam = scope === 'global' ? 'global' : (project || 'cloak-core');
    if (isTauri()) {
      await tauriInvoke<void>('save_secret', {
        scope: scopeParam,
        key,
        value,
        hardwareProtected,
      });

      const maskedPrefix = value.slice(0, Math.min(4, Math.floor(value.length / 3)));
      const maskedSuffix = value.length > 8 ? value.slice(-4) : '';
      const maskedValue = `${maskedPrefix}••••••••${maskedSuffix}`;

      return {
        key,
        maskedValue,
        fullValue: value,
        scope,
        project: scope === 'project' ? scopeParam : undefined,
        updatedAt: hardwareProtected ? 'Touch ID Secure Enclave' : 'Stored in Keychain',
        category: key.toLowerCase().includes('db') || key.toLowerCase().includes('database')
          ? 'database'
          : key.toLowerCase().includes('token')
          ? 'token'
          : 'api-key',
        hardwareStored: true,
        hardwareProtected,
      };
    }

    await delay(120);
    const maskedPrefix = value.slice(0, Math.min(4, Math.floor(value.length / 3)));
    const maskedSuffix = value.length > 8 ? value.slice(-4) : '';
    const maskedValue = `${maskedPrefix}••••••••${maskedSuffix}`;

    const newSecret: SecretItem = {
      key,
      maskedValue,
      fullValue: value,
      scope,
      project: scope === 'project' ? (project || 'cloak-core') : undefined,
      updatedAt: 'Just now',
      category: key.toLowerCase().includes('db') || key.toLowerCase().includes('database')
        ? 'database'
        : key.toLowerCase().includes('token')
        ? 'token'
        : 'api-key',
      hardwareStored: true,
    };

    const existingIndex = mockSecrets.findIndex((s) => s.key === key);
    if (existingIndex >= 0) {
      mockSecrets[existingIndex] = newSecret;
    } else {
      mockSecrets.unshift(newSecret);
    }

    return newSecret;
  },

  async deleteSecret(key: string, scope: string = 'global'): Promise<boolean> {
    if (isTauri()) {
      await tauriInvoke<void>('delete_secret', { scope, key });
      return true;
    }

    await delay(100);
    mockSecrets = mockSecrets.filter((s) => s.key !== key);
    return true;
  },

  async copySecretSecure(key: string, scope: string = 'global'): Promise<boolean> {
    if (isTauri()) {
      await tauriInvoke<void>('copy_secret_secure', { scope, key });
      return true;
    }

    await delay(50);
    const item = mockSecrets.find((s) => s.key === key);
    const val = item?.fullValue || item?.maskedValue || '';
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(val);
    }
    return true;
  },

  async getProxyStatus(): Promise<ProxyStatus> {
    if (isTauri()) {
      try {
        const dto = await tauriInvoke<{
          active: boolean;
          port: number;
          openai_configured: boolean;
          anthropic_configured: boolean;
        }>('check_proxy_status');
        return {
          running: dto.active,
          port: dto.port,
          interceptCount: mockProxyStatus.interceptCount,
        };
      } catch (err) {
        console.warn('Tauri invoke check_proxy_status failed', err);
      }
    }

    await delay(40);
    return { ...mockProxyStatus };
  },

  async toggleProxy(): Promise<ProxyStatus> {
    if (isTauri()) {
      const dto = await tauriInvoke<{
        active: boolean;
        port: number;
        openai_configured: boolean;
        anthropic_configured: boolean;
      }>('toggle_proxy');
      return {
        running: dto.active,
        port: dto.port,
        interceptCount: mockProxyStatus.interceptCount,
      };
    }

    await delay(150);
    mockProxyStatus = {
      ...mockProxyStatus,
      running: !mockProxyStatus.running,
    };
    return { ...mockProxyStatus };
  },

  async getSecurityStatus(): Promise<SecurityStatus> {
    if (isTauri()) {
      try {
        const res = await tauriInvoke<{
          is_unlocked: boolean;
          hardware_backend: string;
          biometric_type: string;
        }>('get_security_status');
        return {
          ...mockSecurityStatus,
          isUnlocked: res.is_unlocked,
          hardwareBackend: res.hardware_backend as SecurityStatus['hardwareBackend'],
        };
      } catch (err) {
        console.warn('Tauri invoke get_security_status failed', err);
      }
    }

    await delay(50);
    return { ...mockSecurityStatus };
  },

  async authenticateVault(): Promise<boolean> {
    if (isTauri()) {
      return await tauriInvoke<boolean>('authenticate_vault');
    }

    await delay(350);
    mockSecurityStatus = { ...mockSecurityStatus, isUnlocked: true };
    return true;
  },

  async lockVault(): Promise<boolean> {
    if (isTauri()) {
      return await tauriInvoke<boolean>('lock_vault');
    }

    await delay(50);
    mockSecurityStatus = { ...mockSecurityStatus, isUnlocked: false };
    return false;
  },

  async toggleVaultLock(): Promise<boolean> {
    if (mockSecurityStatus.isUnlocked) {
      return this.lockVault();
    } else {
      return this.authenticateVault();
    }
  },

  async getPendingJitRequest(): Promise<JitRequest | null> {
    if (isTauri()) {
      const dto = await tauriInvoke<{
        id: string;
        agent: string;
        key: string;
        target_endpoint: string;
        timestamp: string;
      } | null>('get_pending_jit_request');

      if (!dto) return null;
      return {
        id: dto.id,
        agent: dto.agent,
        key: dto.key,
        targetEndpoint: dto.target_endpoint,
        timestamp: dto.timestamp,
        status: 'pending',
      };
    }

    await delay(50);
    return mockPendingJit;
  },

  async respondJit(requestId: string, action: 'deny' | 'once' | 'always', value?: string): Promise<boolean> {
    if (isTauri()) {
      return await tauriInvoke<boolean>('respond_jit', { requestId, action, value: value || null });
    }

    await delay(100);
    if (mockPendingJit && mockPendingJit.id === requestId) {
      mockPendingJit = null;
      if (action !== 'deny') {
        mockProxyStatus.interceptCount += 1;
        mockProxyStatus.lastIntercept = {
          agent: 'claude-code',
          path: '/v1/chat/completions',
          timestamp: 'Just now'
        };
      }
      return true;
    }
    return false;
  },

  async getCliStatus(): Promise<{ isInstalled: boolean; cliPath?: string; targetSymlink?: string; message: string }> {
    if (isTauri()) {
      const dto = await tauriInvoke<{
        is_installed: boolean;
        cli_path?: string;
        target_symlink?: string;
        message: string;
      }>('get_cli_status');
      return {
        isInstalled: dto.is_installed,
        cliPath: dto.cli_path,
        targetSymlink: dto.target_symlink,
        message: dto.message,
      };
    }
    return {
      isInstalled: true,
      cliPath: '/Applications/Cloak.app/Contents/Resources/cloak',
      targetSymlink: '/usr/local/bin/cloak',
      message: 'CLI active at /usr/local/bin/cloak',
    };
  },

  async installCliSymlink(): Promise<{ isInstalled: boolean; cliPath?: string; targetSymlink?: string; message: string }> {
    if (isTauri()) {
      const dto = await tauriInvoke<{
        is_installed: boolean;
        cli_path?: string;
        target_symlink?: string;
        message: string;
      }>('install_cli_symlink');
      return {
        isInstalled: dto.is_installed,
        cliPath: dto.cli_path,
        targetSymlink: dto.target_symlink,
        message: dto.message,
      };
    }
    return {
      isInstalled: true,
      cliPath: '/Applications/Cloak.app/Contents/Resources/cloak',
      targetSymlink: '/usr/local/bin/cloak',
      message: 'Successfully installed CLI symlink at /usr/local/bin/cloak',
    };
  },
};

