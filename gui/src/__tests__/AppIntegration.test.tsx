import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';

describe('App Integration Tests: Cloak Minimal Desktop Vault', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('loads vault cleanly without any popup and renders secrets list directly', async () => {
    render(<App />);

    // Brand and navigation in sidebar
    expect(screen.getByText('Cloak')).toBeInTheDocument();
    expect(screen.getAllByText('All Secrets').length).toBeGreaterThanOrEqual(1);

    // Verify NO intrusive JIT modal on startup
    expect(screen.queryByText('Agent Credential Request')).not.toBeInTheDocument();

    // Verify secrets load directly into view
    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
      expect(screen.getByText('ANTHROPIC_API_KEY')).toBeInTheDocument();
    });
  });

  it('filters secrets when searching with SearchBar', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/Search secrets by name/);
    fireEvent.change(searchInput, { target: { value: 'ANTHROPIC' } });

    await waitFor(() => {
      expect(screen.getByText('ANTHROPIC_API_KEY')).toBeInTheDocument();
      expect(screen.queryByText('OPENAI_API_KEY')).not.toBeInTheDocument();
    });
  });

  it('opens and closes the Add Secret modal using New Secret button', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });

    const newSecretBtn = screen.getByTitle('Store new secret in hardware vault (⌘N)');
    fireEvent.click(newSecretBtn);

    expect(screen.getByText('Store Secret')).toBeInTheDocument();

    const cancelBtn = screen.getByText('Cancel');
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(screen.queryByText('Store Secret')).not.toBeInTheDocument();
    });
  });

  it('allows user to trigger and handle JIT test simulation on demand', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });

    // Click the test simulation button in the sidebar
    const testJitBtn = screen.getByText('Test JIT Prompt');
    fireEvent.click(testJitBtn);

    // Modal appears upon explicit request
    expect(screen.getByText('Agent Credential Request')).toBeInTheDocument();
    expect(screen.getAllByText('OPENAI_API_KEY').length).toBeGreaterThanOrEqual(2);

    // Respond to request
    const allowOnceBtn = screen.getByText('Allow Once');
    fireEvent.click(allowOnceBtn);

    // Modal dismisses
    await waitFor(() => {
      expect(screen.queryByText('Agent Credential Request')).not.toBeInTheDocument();
    });
  });

  it('locks the vault, shields secrets from view, and unlocks on biometric challenge', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });

    // Click Hardware Enclave button to lock
    const lockBtn = screen.getByTitle('Toggle Hardware Keystore lock');
    fireEvent.click(lockBtn);

    // Vault should be locked: secrets hidden, locked screen visible
    await waitFor(() => {
      expect(screen.getByText('Hardware Vault Locked')).toBeInTheDocument();
      expect(screen.queryByText('OPENAI_API_KEY')).not.toBeInTheDocument();
      expect(screen.getByText('Unlock with Touch ID')).toBeInTheDocument();
    });

    // Click Unlock with Touch ID
    const unlockBtn = screen.getByText('Unlock with Touch ID');
    fireEvent.click(unlockBtn);

    // Vault should restore secrets
    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
      expect(screen.queryByText('Hardware Vault Locked')).not.toBeInTheDocument();
    });
  });
});
