import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import AISettingsPage from '../page'

let canEdit = true
let settings: { enabled: boolean; enabled_at?: string; enabled_by?: string } = { enabled: false }
let reason: string | undefined
const update = vi.fn()
const mutateSettings = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canEdit,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/features/ai-triage/api/use-ai-settings', () => ({
  useAISettings: () => ({ data: settings, isLoading: false, mutate: mutateSettings }),
  updateAISettings: (...a: unknown[]) => update(...a),
}))
vi.mock('@/features/ai-triage/api/use-ai-triage-api', () => ({
  useAIConfig: () => ({
    data: { isEnabled: !reason, reason, provider: 'claude', model: 'm', monthlyTokenLimit: 0 },
    mutate: vi.fn(),
  }),
}))

describe('Settings > AI', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canEdit = true
    settings = { enabled: false }
    reason = 'not_enabled'
  })

  it('turns AI triage on only after the consent dialog', async () => {
    update.mockResolvedValue({ enabled: true, enabled_at: '2026-10-19T00:00:00Z' })
    render(<AISettingsPage />)
    expect(screen.getByText(/no finding content is sent/)).toBeInTheDocument()
    expect(screen.getByText('What is sent')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('switch'))
    expect(update).not.toHaveBeenCalled()
    expect(screen.getByText('Turn on AI triage?')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Turn on' }))
    await waitFor(() => expect(update).toHaveBeenCalledWith('t1', true))
  })

  it('turns it off at once', async () => {
    settings = { enabled: true, enabled_at: '2026-10-19T00:00:00Z', enabled_by: 'u1' }
    reason = undefined
    update.mockResolvedValue({ enabled: false })
    render(<AISettingsPage />)
    await userEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(update).toHaveBeenCalledWith('t1', false))
  })

  it('says when the upgrade kept it on', () => {
    settings = { enabled: true, enabled_at: '2026-10-19T00:00:00Z', enabled_by: 'upgrade' }
    reason = undefined
    render(<AISettingsPage />)
    expect(screen.getByText(/used AI triage before this setting existed/)).toBeInTheDocument()
  })

  it('is read-only for someone who may not change it', () => {
    canEdit = false
    render(<AISettingsPage />)
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.getByText(/Only owners and administrators/)).toBeInTheDocument()
  })

  it('warns when no AI provider is set up', () => {
    reason = 'platform_not_configured'
    render(<AISettingsPage />)
    expect(screen.getByText('No AI provider is set up yet')).toBeInTheDocument()
  })
})
