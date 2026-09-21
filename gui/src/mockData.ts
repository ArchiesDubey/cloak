import { SecretItem, ProxyStatus, JitRequest, SecurityStatus } from './types';

export const INITIAL_SECRETS: SecretItem[] = [
  {
    key: 'OPENAI_API_KEY',
    maskedValue: 'sk-proj-••••••••••••••••3819',
    fullValue: 'sk-proj-9A8b7C6d5E4f3G2h1I0jKlMnOpQrStUvWxYz993819',
    scope: 'global',
    updatedAt: '12m ago',
    category: 'api-key',
    hardwareStored: true,
  },
  {
    key: 'ANTHROPIC_API_KEY',
    maskedValue: 'sk-ant-••••••••••••••••8821',
    fullValue: 'sk-ant-api03-abcdef1234567890fedcba0987654321xyz8821',
    scope: 'global',
    updatedAt: '1h ago',
    category: 'api-key',
    hardwareStored: true,
  },
  {
    key: 'DATABASE_URL',
    maskedValue: 'postgres://app:••••••••@10.0.4.12:5432/production',
    fullValue: 'postgres://app:super_secure_pg_pass_2026!@10.0.4.12:5432/production',
    scope: 'project',
    project: 'cloak-core',
    updatedAt: '3h ago',
    category: 'database',
    hardwareStored: true,
  },
  {
    key: 'AWS_SECRET_ACCESS_KEY',
    maskedValue: 'wJalrX••••••••••••••••qX85',
    fullValue: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYqX85',
    scope: 'global',
    updatedAt: '2d ago',
    category: 'token',
    hardwareStored: true,
  },
  {
    key: 'STRIPE_SECRET_KEY',
    maskedValue: 'mock_test_key_0912••••••••••••••••0912',
    fullValue: 'mock_test_key_0912',
    scope: 'project',
    project: 'payment-gateway',
    updatedAt: '4d ago',
    category: 'api-key',
    hardwareStored: true,
  },
  {
    key: 'GITHUB_TOKEN',
    maskedValue: 'ghp_••••••••••••••••K18x',
    fullValue: 'ghp_45AbcDefGhiJklMnoPqrStUvwXyz12345678K18x',
    scope: 'global',
    updatedAt: '5d ago',
    category: 'token',
    hardwareStored: true,
  },
  {
    key: 'CLOUDFLARE_API_TOKEN',
    maskedValue: 'CF_tok_••••••••••••••••Z912',
    fullValue: 'CF_tok_9918237abcde4827103982173abcdef123456789Z912',
    scope: 'project',
    project: 'edge-worker',
    updatedAt: '1w ago',
    category: 'token',
    hardwareStored: true,
  }
];

export const INITIAL_PROXY_STATUS: ProxyStatus = {
  running: true,
  port: 4141,
  interceptCount: 23,
  lastIntercept: {
    agent: 'claude-code',
    path: '/v1/messages',
    timestamp: '14s ago'
  }
};

export const INITIAL_SECURITY_STATUS: SecurityStatus = {
  hardwareBackend: 'Apple Keychain (Secure Enclave)',
  isUnlocked: true,
  biometricType: 'Touch ID',
  memoryLockActive: true,
  coreDumpsDisabled: true,
};

export const INITIAL_PENDING_JIT: JitRequest | null = null;
