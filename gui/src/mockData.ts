import { SecretItem, ProxyStatus, JitRequest, SecurityStatus } from './types';

// Obvious placeholder test fixtures for standalone Vite browser dev only (A1 fix)
export const INITIAL_SECRETS: SecretItem[] = [
  {
    key: 'OPENAI_API_KEY',
    maskedValue: 'mock-••••••••••••••••0001',
    fullValue: 'mock-test-fixture-openai-value-0001',
    scope: 'global',
    updatedAt: '12m ago',
    category: 'api-key',
    hardwareStored: true,
  },
  {
    key: 'ANTHROPIC_API_KEY',
    maskedValue: 'mock-••••••••••••••••0002',
    fullValue: 'mock-test-fixture-anthropic-value-0002',
    scope: 'global',
    updatedAt: '1h ago',
    category: 'api-key',
    hardwareStored: true,
  },
  {
    key: 'DATABASE_URL',
    maskedValue: 'postgres://mock:••••••••@127.0.0.1:5432/test',
    fullValue: 'postgres://mock:test_pass@127.0.0.1:5432/test',
    scope: 'project',
    project: 'cloak-core',
    updatedAt: '3h ago',
    category: 'database',
    hardwareStored: true,
  },
  {
    key: 'AWS_SECRET_ACCESS_KEY',
    maskedValue: 'mock-••••••••••••••••0003',
    fullValue: 'mock-test-fixture-aws-value-0003',
    scope: 'global',
    updatedAt: '2d ago',
    category: 'token',
    hardwareStored: true,
  }
];

export const INITIAL_PROXY_STATUS: ProxyStatus = {
  running: false,
  port: 4141,
  interceptCount: 0,
};

export const INITIAL_SECURITY_STATUS: SecurityStatus = {
  hardwareBackend: 'macOS Keychain (OS Keyring)',
  isUnlocked: false, // S2: Vault starts locked by default
  biometricType: 'Touch ID',
  memoryLockActive: true,
  coreDumpsDisabled: true,
};

export const INITIAL_PENDING_JIT: JitRequest | null = null;
