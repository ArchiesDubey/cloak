import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { SecretCard } from '../components/SecretCard';
import { SearchBar } from '../components/SearchBar';
import { JitApprovalModal } from '../components/JitApprovalModal';
import { AddSecretModal } from '../components/AddSecretModal';
import { Sidebar } from '../components/Sidebar';
import { SecretItem, JitRequest, ProxyStatus, SecurityStatus } from '../types';

describe('GUI Component Tests: Cloak Minimal Desktop', () => {
  const mockSecret: SecretItem = {
    key: 'OPENAI_API_KEY',
    maskedValue: 'sk-p••••••••9999',
    scope: 'global',
    updatedAt: 'Stored in Keychain',
    category: 'api-key',
    hardwareStored: true,
  };

  it('SecretCard renders key, scope badge, and masked value by default', () => {
    render(
      <SecretCard
        secret={mockSecret}
        onRevealToggle={vi.fn().mockResolvedValue('sk-proj-actual-secret')}
        onDelete={vi.fn()}
        onCopySuccess={vi.fn()}
      />
    );

    expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    expect(screen.getByText('sk-p••••••••9999')).toBeInTheDocument();
    expect(screen.getByText('GLOBAL')).toBeInTheDocument();
  });

  it('SecretCard toggles reveal state on eye click', async () => {
    const revealMock = vi.fn().mockResolvedValue('sk-proj-actual-secret');
    render(
      <SecretCard
        secret={mockSecret}
        onRevealToggle={revealMock}
        onDelete={vi.fn()}
        onCopySuccess={vi.fn()}
      />
    );

    const revealBtn = screen.getByTitle('Decrypt & reveal value');
    fireEvent.click(revealBtn);

    expect(revealMock).toHaveBeenCalledWith('OPENAI_API_KEY', false);
    const revealedVal = await screen.findByText('sk-proj-actual-secret');
    expect(revealedVal).toBeInTheDocument();
  });

  it('SearchBar updates query and responds to category click', () => {
    const onSearch = vi.fn();
    const onCategory = vi.fn();
    render(
      <SearchBar
        searchQuery=""
        onSearchChange={onSearch}
        activeCategory="all"
        onCategoryChange={onCategory}
        categories={[
          { id: 'all', label: 'All', count: 5 },
          { id: 'api-key', label: 'API Keys', count: 3 },
        ]}
      />
    );

    const input = screen.getByPlaceholderText(/Search secrets by name/);
    fireEvent.change(input, { target: { value: 'OPENAI' } });
    expect(onSearch).toHaveBeenCalledWith('OPENAI');

    const apiKeyTag = screen.getByText('API Keys');
    fireEvent.click(apiKeyTag);
    expect(onCategory).toHaveBeenCalledWith('api-key');
  });

  it('JitApprovalModal displays agent request and triggers approval buttons', () => {
    const mockRequest: JitRequest = {
      id: 'req_123',
      agent: 'Claude Code',
      key: 'OPENAI_API_KEY',
      timestamp: 'Just now',
      targetEndpoint: 'https://api.openai.com/v1/chat/completions',
      processPid: 42100,
      status: 'pending',
    };
    const onRespond = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    render(
      <JitApprovalModal
        request={mockRequest}
        onRespond={onRespond}
        onClose={onClose}
      />
    );

    expect(screen.getByText('Agent Credential Request')).toBeInTheDocument();
    expect(screen.getByText('Claude Code (PID: 42100)')).toBeInTheDocument();
    expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument();
    expect(screen.getByText('https://api.openai.com/v1/chat/completions')).toBeInTheDocument();

    const allowOnceBtn = screen.getByText('Allow Once');
    fireEvent.click(allowOnceBtn);
    expect(onRespond).toHaveBeenCalledWith('req_123', 'once');

    const alwaysAllowBtn = screen.getByText('Always Allow');
    fireEvent.click(alwaysAllowBtn);
    expect(onRespond).toHaveBeenCalledWith('req_123', 'always');

    const denyBtn = screen.getByText('Deny');
    fireEvent.click(denyBtn);
    expect(onRespond).toHaveBeenCalledWith('req_123', 'deny');
  });

  it('AddSecretModal commits secret with correct scope and uppercase formatting', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    render(
      <AddSecretModal
        isOpen={true}
        onClose={onClose}
        onSave={onSave}
        defaultScope="global"
        currentProjectName="my-web-app"
      />
    );

    expect(screen.getByText('Store Secret')).toBeInTheDocument();

    const keyInput = screen.getByPlaceholderText('OPENAI_API_KEY');
    const valInput = screen.getByPlaceholderText('sk-proj-...');

    fireEvent.change(keyInput, { target: { value: 'anthropic_api_key' } });
    fireEvent.change(valInput, { target: { value: 'sk-ant-secret12345' } });

    const submitBtn = screen.getByText('Save Secret');
    await act(async () => {
      fireEvent.click(submitBtn);
    });

    expect(onSave).toHaveBeenCalledWith('ANTHROPIC_API_KEY', 'sk-ant-secret12345', 'global', undefined);
  });

  it('Sidebar renders branding, vault navigation, and hardware status', () => {
    const mockProxy: ProxyStatus = {
      running: true,
      port: 4141,
      interceptCount: 3,
    };
    const mockSecurity: SecurityStatus = {
      hardwareBackend: 'Apple Keychain (Secure Enclave)',
      isUnlocked: true,
      biometricType: 'Touch ID',
      memoryLockActive: true,
      coreDumpsDisabled: true,
    };

    render(
      <Sidebar
        currentScope="all"
        onSelectScope={vi.fn()}
        selectedProject={null}
        onSelectProject={vi.fn()}
        projectList={['cloak-core', 'web-app']}
        counts={{ all: 7, global: 4, project: 3 }}
        proxyStatus={mockProxy}
        onToggleProxy={vi.fn()}
        securityStatus={mockSecurity}
        onToggleLock={vi.fn()}
        onSimulateJit={vi.fn()}
        pendingJitCount={0}
      />
    );

    expect(screen.getByText('Cloak')).toBeInTheDocument();
    expect(screen.getByText('v0.1')).toBeInTheDocument();
    expect(screen.getByText('All Secrets')).toBeInTheDocument();
    expect(screen.getByText('Global (Keychain)')).toBeInTheDocument();
    expect(screen.getByText('cloak-core')).toBeInTheDocument();
    expect(screen.getByText('AI Proxy :4141')).toBeInTheDocument();
    expect(screen.getByText('Hardware Enclave')).toBeInTheDocument();
  });
});
