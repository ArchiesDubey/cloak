export type SecretScope = 'global' | 'project';
export type ScopeFilter = 'all' | 'global' | 'project';

export interface SecretItem {
  key: string;
  maskedValue: string;
  fullValue?: string;
  scope: SecretScope;
  project?: string;
  updatedAt: string;
  category: 'api-key' | 'database' | 'token' | 'certificate' | 'env';
  hardwareStored: boolean;
}

export interface ProxyStatus {
  running: boolean;
  port: number;
  interceptCount: number;
  lastIntercept?: {
    agent: string;
    path: string;
    timestamp: string;
  };
}

export interface JitRequest {
  id: string;
  agent: string;
  key: string;
  timestamp: string;
  targetEndpoint: string;
  processPid?: number;
  status: 'pending' | 'allowed_once' | 'always_allowed' | 'denied';
}

export interface SecurityStatus {
  hardwareBackend: 'Apple Keychain (Secure Enclave)' | 'Windows Credential Manager' | 'Linux Secret Service' | 'Encrypted File Vault';
  isUnlocked: boolean;
  biometricType: 'Touch ID' | 'Windows Hello' | 'Master Key' | 'Hardware Token';
  memoryLockActive: boolean;
  coreDumpsDisabled: boolean;
}
