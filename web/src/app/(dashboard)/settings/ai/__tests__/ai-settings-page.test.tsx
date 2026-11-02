import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import AISettingsPage from '../page'

let canEdit = true
let perms: string[] = ['ai_knowledge:read', 'audit:read']
const base = {
  enabled: false,
  source: 'platform',
  provider: '',
  base_url: '',
  model: '',
  key: { set: false },
  own_provider_allowed: true,
  providers: ['claude', 'openai', 'gemini', 'openai_compatible'],
}
let settings: Record<string, unknown> = { ...base }
let reason: string | undefined
let limit = 0
let used = 0
const update = vi.fn()
const mutateSettings = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canEdit,
  useHasPermission: (p: string) => perms.includes(p),
}))
vi.mock('@/features/ai-triage/components/ai-knowledge-section', () => ({
  AIKnowledgeSection: () => <p>knowledge-section</p>,
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['audit', 'ai_triage'], isLoading: false }),
}))
vi.mock('@/features/ai-triage/components/ai-activity-card', () => ({
  AIActivityCard: () => <p>activity-card</p>,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/features/ai-triage/api/use-ai-settings', () => ({
  useAISettings: () => ({ data: settings, isLoading: false, mutate: mutateSettings }),
  updateAISettings: (...a: unknown[]) => update(...a),
}))
vi.mock('@/features/ai-triage/api/use-ai-masking', async (orig) => ({
  ...(await orig<typeof import('@/features/ai-triage/api/use-ai-masking')>()),
  useAIMasking: () => ({ data: null, mutate: vi.fn() }),
}))
vi.mock('@/features/ai-triage/components/ai-auto-triage-card', () => ({
  AIAutoTriageCard: () => null,
}))
vi.mock('@/features/ai-triage/components/ai-use-cases-section', () => ({
  AIUseCasesSection: () => <p>use-cases-section</p>,
}))
vi.mock('@/features/ai-triage/components/ai-agents-section', () => ({
  AIAgentsSection: () => null,
}))
vi.mock('@/features/ai-triage/api/use-ai-triage-api', () => ({
  useAIConfig: () => ({
    data: {
      isEnabled: !reason,
      reason,
      provider: 'claude',
      model: 'm',
      monthlyTokenLimit: limit,
      tokensUsedThisMonth: used,
      autoTriageEnabled: false,
    },
    mutate: vi.fn(),
  }),
}))

describe('Settings > AI', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canEdit = true
    settings = { ...base }
    reason = 'not_enabled'
    perms = ['ai_knowledge:read', 'audit:read']
    limit = 0
    used = 0
    window.history.replaceState(null, '', '/settings/ai')
  })

  it('turns AI triage on only after the consent dialog', async () => {
    update.mockResolvedValue({ ...base, enabled: true, enabled_at: '2026-10-19T00:00:00Z' })
    render(<AISettingsPage />)
    expect(screen.getByText(/no finding content is sent/)).toBeInTheDocument()
    expect(screen.getByText('What is sent')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('switch', { name: /Turn on AI triage/ }))
    expect(update).not.toHaveBeenCalled()
    expect(screen.getByText('Turn on AI triage?')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Turn on' }))
    await waitFor(() => expect(update).toHaveBeenCalledWith({ enabled: true }))
  })

  it('turns it off at once', async () => {
    settings = { ...base, enabled: true, enabled_at: '2026-10-19T00:00:00Z', enabled_by: 'u1' }
    reason = undefined
    update.mockResolvedValue({ ...base, enabled: false })
    render(<AISettingsPage />)
    await userEvent.click(screen.getByRole('switch', { name: /Turn on AI triage/ }))
    await waitFor(() => expect(update).toHaveBeenCalledWith({ enabled: false }))
  })

  it('says when the upgrade kept it on', () => {
    settings = { ...base, enabled: true, enabled_at: '2026-10-19T00:00:00Z', enabled_by: 'upgrade' }
    reason = undefined
    render(<AISettingsPage />)
    expect(screen.getByText(/used AI triage before this setting existed/)).toBeInTheDocument()
  })

  it('is read-only for someone who may not change it', () => {
    canEdit = false
    render(<AISettingsPage />)
    expect(screen.getByRole('switch', { name: /Turn on AI triage/ })).toBeDisabled()
    expect(screen.getByText(/Only owners and administrators/)).toBeInTheDocument()
  })

  it('warns when no AI provider is set up', () => {
    reason = 'platform_not_configured'
    render(<AISettingsPage />)
    expect(screen.getByText('No AI provider is set up yet')).toBeInTheDocument()
  })

  it('sums the state up in a strip whose tiles open the tab that changes it', async () => {
    limit = 1000
    used = 250
    render(<AISettingsPage />)
    expect(screen.getByText('25%')).toBeInTheDocument()
    expect(screen.queryByText('Use and limits')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /This month/ }))
    expect(await screen.findByText('Use and limits')).toBeInTheDocument()
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '250')
  })

  it('shows the Knowledge and Activity tabs only to those who may read them', () => {
    perms = []
    render(<AISettingsPage />)
    expect(screen.getByRole('tab', { name: 'Provider' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Knowledge' })).not.toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Activity' })).not.toBeInTheDocument()
  })

  it('opens the tab named by a settings search anchor', async () => {
    window.history.replaceState(null, '', '/settings/ai#ai-knowledge')
    render(<AISettingsPage />)
    expect(await screen.findByText('knowledge-section')).toBeInTheDocument()
  })

  it('has a Use cases tab, opened by its settings search anchor', async () => {
    window.history.replaceState(null, '', '/settings/ai#ai-use-cases')
    render(<AISettingsPage />)
    expect(screen.getByRole('tab', { name: 'Use cases' })).toBeInTheDocument()
    expect(await screen.findByText('use-cases-section')).toBeInTheDocument()
  })

  it('keeps what is sent one click away', async () => {
    render(<AISettingsPage />)
    expect(screen.queryByText(/file path, CVE/)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'What is sent' }))
    expect(screen.getByText(/file path, CVE/)).toBeInTheDocument()
  })
})
