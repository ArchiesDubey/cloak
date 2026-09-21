import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../App';
import { api } from '../api';

describe('App Integration Tests: Cloak Hybrid Workstation & HUD', () => {
  beforeEach(() => {
    // Reset any mock state
    vi.restoreAllMocks();
  });

  it('handles in-flight JIT intercept modal and reveals secrets upon response', async () => {
    render(<App />);

    // Check Header branding is present
    expect(screen.getByText('[ CLOAK ]')).toBeInTheDocument();
    expect(screen.getByText('LOCAL-FIRST HARDWARE VAULT')).toBeInTheDocument();

    // Initial load triggers JIT modal if pending
    await waitFor(() => {
      expect(screen.getByText('[ JIT SECURITY INTERCEPT ]')).toBeInTheDocument();
    });

    // Respond to JIT intercept
    const allowBtn = screen.getByText('ALLOW ONCE');
    fireEvent.click(allowBtn);

    // Modal should dismiss
    await waitFor(() => {
      expect(screen.queryByText('[ JIT SECURITY INTERCEPT ]')).not.toBeInTheDocument();
    });

    // Secrets list now fully visible
    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
      expect(screen.getByText('ANTHROPIC_API_KEY')).toBeInTheDocument();
    });
  });

  it('filters secrets when searching with SearchBar', async () => {
    vi.spyOn(api, 'getPendingJitRequest').mockResolvedValue(null);
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/Filter secrets by name/);
    fireEvent.change(searchInput, { target: { value: 'ANTHROPIC' } });

    await waitFor(() => {
      expect(screen.getByText('ANTHROPIC_API_KEY')).toBeInTheDocument();
      expect(screen.queryByText('OPENAI_API_KEY')).not.toBeInTheDocument();
    });
  });

  it('opens and closes the Add Secret modal using STORE button', async () => {
    vi.spyOn(api, 'getPendingJitRequest').mockResolvedValue(null);
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    });

    const storeBtn = screen.getByTitle('Store new secret in hardware vault (⌘N)');
    fireEvent.click(storeBtn);

    expect(screen.getByText('[ STORE HARDWARE CREDENTIAL ]')).toBeInTheDocument();

    const cancelBtn = screen.getByText('CANCEL (ESC)');
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(screen.queryByText('[ STORE HARDWARE CREDENTIAL ]')).not.toBeInTheDocument();
    });
  });

  it('toggles compact HUD mode vs workstation mode', async () => {
    vi.spyOn(api, 'getPendingJitRequest').mockResolvedValue(null);
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTitle('Collapse to Compact HUD (⌘E)')).toBeInTheDocument();
    });

    const compactToggleBtn = screen.getByTitle('Collapse to Compact HUD (⌘E)');
    fireEvent.click(compactToggleBtn);

    await waitFor(() => {
      expect(screen.getByTitle('Expand to Desktop Dashboard (⌘E)')).toBeInTheDocument();
    });
  });
});
