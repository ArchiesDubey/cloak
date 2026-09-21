import { invoke } from '@tauri-apps/api/core';
import { SecretItem, ProxyStatus, SecurityStatus, JitRequest, SecretScope } from './types';
import { INITIAL_SECRETS, INITIAL_PROXY_STATUS, INITIAL_SECURITY_STATUS, INITIAL_PENDING_JIT } from './mockData';

// Check if running inside a Tauri desktop container
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
  throw new Error('Tauri invoke IPC is not available');
}

// In-memory mock storage for browser testing / demo mode
let mockSecrets: SecretItem[] = [...INITIAL_SECRETS];
let mockProxyStatus: ProxyStatus = { ...INITIAL_PROXY_STATUS };
let mockSecurityStatus: SecurityStatus = { ...INITIAL_SECURITY_STATUS };
let mockPendingJit: JitRequest | null = INITIAL_PENDING_JIT;

// Helper to simulate realistic hardware keystore delay
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const api = {
  isDesktopApp: (): boolean => isTauri(),

  async listSecrets(scope?: string): Promise<SecretItem[]> {
    if (isTauri()) {
      try {
        return await tauriInvoke<SecretItem[]>('list_secrets', { scope });
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
    }

    await delay(60);
    if (!scope || scope === 'all') {
      return [...mockSecrets];
    }
    return mockSecrets.filter((s) => s.scope === scope);
  },

  async getSecret(key: string, reveal: boolean): Promise<string> {
    if (isTauri()) {
      try {
        return await tauriInvoke<string>('get_secret', { key, reveal });
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
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
    project?: string
  ): Promise<SecretItem> {
    if (isTauri()) {
      try {
        return await tauriInvoke<SecretItem>('set_secret', { key, value, scope, project });
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
    }

    await delay(120);
    const maskedPrefix = value.slice(0, Math.min(6, Math.floor(value.length / 3)));
    const maskedSuffix = value.length > 8 ? value.slice(-4) : '';
    const maskedValue = `${maskedPrefix}••••••••${maskedSuffix}`;

    const existingIndex = mockSecrets.findIndex((s) => s.key === key);
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

    if (existingIndex >= 0) {
      mockSecrets[existingIndex] = newSecret;
    } else {
      mockSecrets.unshift(newSecret);
    }

    return newSecret;
  },

  async deleteSecret(key: string): Promise<boolean> {
    if (isTauri()) {
      try {
        return await tauriInvoke<boolean>('delete_secret', { key });
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
    }

    await delay(100);
    mockSecrets = mockSecrets.filter((s) => s.key !== key);
    return true;
  },

  async getProxyStatus(): Promise<ProxyStatus> {
    if (isTauri()) {
      try {
        return await tauriInvoke<ProxyStatus>('get_proxy_status');
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
    }

    await delay(40);
    return { ...mockProxyStatus };
  },

  async toggleProxy(): Promise<ProxyStatus> {
    if (isTauri()) {
      try {
        return await tauriInvoke<ProxyStatus>('toggle_proxy');
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
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
          hardwareBackend: 'Apple Keychain (Secure Enclave)',
          biometricType: 'Touch ID',
        };
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
    }

    await delay(40);
    return { ...mockSecurityStatus };
  },

  async authenticateVault(): Promise<boolean> {
    if (isTauri()) {
      try {
        const success = await tauriInvoke<boolean>('authenticate_vault');
        mockSecurityStatus.isUnlocked = success;
        return success;
      } catch (err) {
        console.error('[Cloak] authenticate_vault error:', err);
        return false;
      }
    }

    await delay(250);
    mockSecurityStatus.isUnlocked = true;
    return true;
  },

  async lockVault(): Promise<boolean> {
    if (isTauri()) {
      try {
        await tauriInvoke<boolean>('lock_vault');
        mockSecurityStatus.isUnlocked = false;
        return false;
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock lock', err);
      }
    }

    await delay(80);
    mockSecurityStatus.isUnlocked = false;
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
      try {
        return await tauriInvoke<JitRequest | null>('get_pending_jit_request');
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
    }

    await delay(50);
    return mockPendingJit;
  },

  async respondJit(requestId: string, action: 'deny' | 'once' | 'always'): Promise<boolean> {
    if (isTauri()) {
      try {
        return await tauriInvoke<boolean>('respond_jit', { requestId, action });
      } catch (err) {
        console.warn('Tauri invoke failed, falling back to mock storage', err);
      }
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
};
