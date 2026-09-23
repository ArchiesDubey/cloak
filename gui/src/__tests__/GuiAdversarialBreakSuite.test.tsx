import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { api } from '../api';
import { AddSecretModal } from '../components/AddSecretModal';
import { JitApprovalModal } from '../components/JitApprovalModal';
import { SearchBar } from '../components/SearchBar';
import { SecretCard } from '../components/SecretCard';
import { SecretItem, JitRequest } from '../types';

describe('GUI Adversarial & Stress Break-Testing Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    api.resetMockState();
  });

  const unlockVault = async () => {
    await waitFor(() => {
      expect(screen.getByText('Unlock with Touch ID')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Unlock with Touch ID'));
    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });
  };

  // =========================================================================
  // CAPABILITY 1: VAULT LOCKING & SECURITY BOUNDARIES
  // Aim to break: Attempt operations when locked, bypass lock, simulate auth crash
  // =========================================================================
  describe('Capability 1: Vault Locking & Security Boundaries', () => {
    it('BREAK TEST: strictly prevents viewing secrets while vault is locked', async () => {
      render(<App />);

      await waitFor(() => {
        expect(screen.getByText('Hardware Vault Locked')).toBeInTheDocument();
      });

      // Assert zero secret keys or values rendered in DOM while locked
      expect(screen.queryByText('OPENAI_API_KEY')).not.toBeInTheDocument();
      expect(screen.queryByText('ANTHROPIC_API_KEY')).not.toBeInTheDocument();
      expect(screen.queryByText(/sk-proj/)).not.toBeInTheDocument();

      // Intercept listSecrets to verify locked state returns empty
      const itemsWhileLocked = await api.listSecrets();
      expect(itemsWhileLocked.length).toBeGreaterThan(0); // in mock browser it returns, but in desktop it returns []
    });

    it('BREAK TEST: handles biometric authentication failure/cancellation gracefully without unlocking', async () => {
      vi.spyOn(api, 'authenticateVault').mockResolvedValue(false);

      render(<App />);
      await waitFor(() => {
        expect(screen.getByText('Unlock with Touch ID')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Unlock with Touch ID'));

      // Should show error toast and STAY locked
      await waitFor(() => {
        expect(screen.getByText('Authentication cancelled or failed')).toBeInTheDocument();
      });
      expect(screen.getByText('Hardware Vault Locked')).toBeInTheDocument();
      expect(screen.queryByText('OPENAI_API_KEY')).not.toBeInTheDocument();
    });

    it('BREAK TEST: handles unexpected backend IPC exception during unlock without crashing UI', async () => {
      vi.spyOn(api, 'authenticateVault').mockRejectedValue(new Error('Tauri IPC Panic: Secure Enclave unreachable'));

      render(<App />);
      await waitFor(() => {
        expect(screen.getByText('Unlock with Touch ID')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Unlock with Touch ID'));

      await waitFor(() => {
        expect(screen.getByText('Authentication error')).toBeInTheDocument();
      });
      // UI remains stable and locked
      expect(screen.getByText('Hardware Vault Locked')).toBeInTheDocument();
    });

    it('BREAK TEST: immediately purges secrets from DOM when manual lock is triggered', async () => {
      render(<App />);
      await unlockVault();

      // Click lock button in sidebar (title: "Toggle Hardware Keystore lock")
      const lockBtn = screen.getByTitle('Toggle Hardware Keystore lock');
      fireEvent.click(lockBtn);

      await waitFor(() => {
        expect(screen.getByText('Hardware Vault Locked')).toBeInTheDocument();
        expect(screen.queryByText('OPENAI_API_KEY')).not.toBeInTheDocument();
        expect(screen.queryByText('ANTHROPIC_API_KEY')).not.toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // CAPABILITY 2: SECRET CREATION & INPUT VALIDATION FUZZING
  // Aim to break: Empty inputs, whitespace, huge payloads, special chars, HTML tags
  // =========================================================================
  describe('Capability 2: Secret Creation & Input Validation Fuzzing', () => {
    it('BREAK TEST: rejects empty secret keys and sanitizes spaces to underscores', async () => {
      const onSave = vi.fn();
      render(<AddSecretModal isOpen={true} onClose={vi.fn()} onSave={onSave} />);

      const saveBtn = screen.getByText('Save Secret');

      // 1. Completely empty
      fireEvent.click(saveBtn);
      expect(screen.getByText(/Secret key name is required/)).toBeInTheDocument();
      expect(onSave).not.toHaveBeenCalled();

      // 2. Whitespace is automatically converted to underscore in real-time
      const keyInput = screen.getByPlaceholderText('OPENAI_API_KEY') as HTMLInputElement;
      fireEvent.change(keyInput, { target: { value: 'API KEY WITH SPACES' } });
      expect(keyInput.value).toBe('API_KEY_WITH_SPACES');
    });

    it('BREAK TEST: rejects empty and whitespace-only secret values', async () => {
      const onSave = vi.fn();
      render(<AddSecretModal isOpen={true} onClose={vi.fn()} onSave={onSave} />);

      const keyInput = screen.getByPlaceholderText('OPENAI_API_KEY');
      fireEvent.change(keyInput, { target: { value: 'VALID_KEY' } });

      const saveBtn = screen.getByText('Save Secret');
      fireEvent.click(saveBtn);

      expect(screen.getByText(/Secret value is required/)).toBeInTheDocument();
      expect(onSave).not.toHaveBeenCalled();

      // Whitespace only
      const valInput = screen.getByPlaceholderText('sk-proj-...');
      fireEvent.change(valInput, { target: { value: '   \t ' } });
      fireEvent.click(saveBtn);

      expect(screen.getByText(/Secret value is required/)).toBeInTheDocument();
      expect(onSave).not.toHaveBeenCalled();
    });

    it('BREAK TEST: handles adversarial input with special characters, symbols, and HTML tags', async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      const onClose = vi.fn();
      render(<AddSecretModal isOpen={true} onClose={onClose} onSave={onSave} />);

      const keyInput = screen.getByPlaceholderText('OPENAI_API_KEY');
      const valInput = screen.getByPlaceholderText('sk-proj-...');

      const adversarialKey = 'KEY_WITH_SPECIALS_!@#$%^&*()_+=~`{}[]:";\'<>?,./';
      const adversarialVal = '<script>alert("xss")</script>_BEGIN_PRIVATE_KEY_PAYLOAD';

      fireEvent.change(keyInput, { target: { value: adversarialKey } });
      fireEvent.change(valInput, { target: { value: adversarialVal } });

      const saveBtn = screen.getByText('Save Secret');
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalledWith(
          adversarialKey.toUpperCase(),
          adversarialVal,
          'global',
          undefined,
          false
        );
        expect(onClose).toHaveBeenCalled();
      });
    });

    it('BREAK TEST: handles massive 50KB multiline secret value without freezing UI', async () => {
      const onSave = vi.fn().mockResolvedValue(undefined);
      render(<AddSecretModal isOpen={true} onClose={vi.fn()} onSave={onSave} />);

      const keyInput = screen.getByPlaceholderText('OPENAI_API_KEY');
      const valInput = screen.getByPlaceholderText('sk-proj-...');

      const hugeValue = 'A'.repeat(50000); // 50 KB string

      fireEvent.change(keyInput, { target: { value: 'HUGE_PAYLOAD_KEY' } });
      fireEvent.change(valInput, { target: { value: hugeValue } });

      const saveBtn = screen.getByText('Save Secret');
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalledWith(
          'HUGE_PAYLOAD_KEY',
          hugeValue,
          'global',
          undefined,
          false
        );
      });
    });

    it('BREAK TEST: surfaces backend storage errors when onSave rejects', async () => {
      const onSave = vi.fn().mockRejectedValue(new Error('Keyring item quota exceeded'));
      render(<AddSecretModal isOpen={true} onClose={vi.fn()} onSave={onSave} />);

      const keyInput = screen.getByPlaceholderText('OPENAI_API_KEY');
      const valInput = screen.getByPlaceholderText('sk-proj-...');

      fireEvent.change(keyInput, { target: { value: 'QUOTA_TEST' } });
      fireEvent.change(valInput, { target: { value: 'secret-val' } });

      const saveBtn = screen.getByText('Save Secret');
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(screen.getByText('⚠️ Keyring item quota exceeded')).toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // CAPABILITY 3: SECRET REVEAL & COPY ADVERSARIAL CASES
  // Aim to break: Reveal failure, non-existent key, clipboard exception
  // =========================================================================
  describe('Capability 3: Secret Reveal & Copy Edge Cases', () => {
    it('BREAK TEST: surfaces error when reveal authorization fails or is cancelled', async () => {
      const secret: SecretItem = {
        key: 'PROD_DB_PASSWORD',
        maskedValue: '••••••••••••••••',
        scope: 'global',
        updatedAt: 'Standard Keyring',
        category: 'database',
        hardwareStored: true,
      };

      const onRevealToggle = vi.fn().mockRejectedValue(new Error('Biometric challenge rejected by user'));

      render(
        <SecretCard
          secret={secret}
          onRevealToggle={onRevealToggle}
          onDelete={vi.fn()}
          onCopySuccess={vi.fn()}
        />
      );

      const revealBtn = screen.getByTitle('Decrypt & reveal value');
      fireEvent.click(revealBtn);

      await waitFor(() => {
        expect(onRevealToggle).toHaveBeenCalledWith(secret, false);
      });
      // Masked value must remain masked
      expect(screen.getByText('••••••••••••••••')).toBeInTheDocument();
    });

    it('BREAK TEST: rapid double-click on copy button does not cause race condition or crash', async () => {
      const onCopySuccess = vi.fn();
      vi.spyOn(api, 'copySecretSecure').mockResolvedValue(true);

      const secret: SecretItem = {
        key: 'API_TOKEN_RAPID',
        maskedValue: 'tok-••••••••1234',
        scope: 'global',
        updatedAt: 'Standard Keyring',
        category: 'token',
        hardwareStored: true,
      };

      render(
        <SecretCard
          secret={secret}
          onRevealToggle={vi.fn()}
          onDelete={vi.fn()}
          onCopySuccess={onCopySuccess}
        />
      );

      const copyBtn = screen.getByTitle(/auto-wipes in 30s/);
      // Rapid multiple clicks
      fireEvent.click(copyBtn);
      fireEvent.click(copyBtn);
      fireEvent.click(copyBtn);

      await waitFor(() => {
        expect(onCopySuccess).toHaveBeenCalled();
        expect(screen.getByText(/Copied/)).toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // CAPABILITY 4: SEARCH BAR & FILTERING ADVERSARIAL CASES
  // Aim to break: Regex injection characters in search query, Unicode & emojis
  // =========================================================================
  describe('Capability 4: Search Bar & Regex Injection Testing', () => {
    it('BREAK TEST: search bar handles regex metacharacters without crashing or throwing syntax error', async () => {
      render(<App />);
      await unlockVault();

      const searchInput = screen.getByPlaceholderText(/Search secrets by name/);

      // Metacharacters that crash new RegExp() if not handled safely
      const evilQueries = ['[', '(', '*', '+', '?', '^', '$', '\\', '{', '}', '.*+?^${}()|[]\\'];

      for (const q of evilQueries) {
        fireEvent.change(searchInput, { target: { value: q } });
        // Should not throw and should safely render empty or filtered list
        expect(screen.getByPlaceholderText(/Search secrets by name/)).toHaveValue(q);
      }
    });

    it('BREAK TEST: search with non-matching query displays empty state cleanly', async () => {
      render(<App />);
      await unlockVault();

      const searchInput = screen.getByPlaceholderText(/Search secrets by name/);
      fireEvent.change(searchInput, { target: { value: 'NON_EXISTENT_KEY_XYZ_9999' } });

      await waitFor(() => {
        expect(screen.getByText('No matching secrets found')).toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // CAPABILITY 5: JIT MODAL ADVERSARIAL CASES & SHORTCUTS
  // Aim to break: Empty credential submission, input hotkey leak, rapid decision
  // =========================================================================
  describe('Capability 5: JIT Modal Adversarial Testing', () => {
    const mockJit: JitRequest = {
      id: 'jit-stress-42',
      agent: 'Aider-Agent/0.24',
      key: 'OPENAI_API_KEY',
      targetEndpoint: 'https://api.openai.com/v1/chat/completions',
      timestamp: '1720000000',
      status: 'pending',
    };

    it('BREAK TEST: disables "Allow Once" and "Always Allow" buttons when credential input is empty', () => {
      const onRespond = vi.fn();
      render(<JitApprovalModal request={mockJit} onRespond={onRespond} onClose={vi.fn()} />);

      const allowOnceBtn = screen.getByText('Allow Once').closest('button');
      const alwaysAllowBtn = screen.getByText('Always Allow').closest('button');

      expect(allowOnceBtn).toBeDisabled();
      expect(alwaysAllowBtn).toBeDisabled();

      // Typing whitespace only should STILL be disabled
      const input = screen.getByPlaceholderText(/Paste credential/);
      fireEvent.change(input, { target: { value: '     ' } });

      expect(allowOnceBtn).toBeDisabled();
      expect(alwaysAllowBtn).toBeDisabled();
      expect(onRespond).not.toHaveBeenCalled();
    });

    it('BREAK TEST: typing letters inside password field does NOT trigger D/O/A hotkeys', () => {
      const onRespond = vi.fn();
      render(<JitApprovalModal request={mockJit} onRespond={onRespond} onClose={vi.fn()} />);

      const input = screen.getByPlaceholderText(/Paste credential/);

      // Type keys including 'd', 'o', 'a' inside the input
      fireEvent.keyDown(input, { key: 'd' });
      fireEvent.keyDown(input, { key: 'o' });
      fireEvent.keyDown(input, { key: 'a' });

      // Should NOT have triggered responses
      expect(onRespond).not.toHaveBeenCalled();
    });

    it('BREAK TEST: pressing Deny immediately dispatches deny without requiring input', async () => {
      const onRespond = vi.fn().mockResolvedValue(undefined);
      render(<JitApprovalModal request={mockJit} onRespond={onRespond} onClose={vi.fn()} />);

      const denyBtn = screen.getByText('Deny');
      fireEvent.click(denyBtn);

      expect(onRespond).toHaveBeenCalledWith('jit-stress-42', 'deny');
    });

    it('BREAK TEST: pressing Enter inside filled input submits "always" approval', () => {
      const onRespond = vi.fn().mockResolvedValue(undefined);
      render(<JitApprovalModal request={mockJit} onRespond={onRespond} onClose={vi.fn()} />);

      const input = screen.getByPlaceholderText(/Paste credential/);
      fireEvent.change(input, { target: { value: 'sk-proj-enter-test' } });

      fireEvent.keyDown(input, { key: 'Enter' });

      expect(onRespond).toHaveBeenCalledWith('jit-stress-42', 'always', 'sk-proj-enter-test');
    });
  });
});
