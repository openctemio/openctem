import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'
import { AITriageButton } from '../ai-triage-button'
import type { AIConfig } from '../../types'

// Radix Tooltip/Popover measure themselves on hover; jsdom has no
// ResizeObserver (without this the click tests fail at random).
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

let hasModule = true
let config: Partial<AIConfig> | undefined
let role = 'member'
const trigger = vi.fn()
const mutateConfig = vi.fn()
const toastError = vi.fn()

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a), info: vi.fn() },
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useHasModule: () => ({ hasModule, isLoading: false }),
}))
vi.mock('@/hooks/use-websocket', () => ({
  useTriageChannel: () => ({ isSubscribed: false }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 'acme', role } }),
}))
vi.mock('../../api', () => ({
  useAIConfig: () => ({ data: config, isLoading: false, mutate: mutateConfig }),
  useRequestTriage: () => ({ trigger }),
  useTriageResult: () => ({ data: null, mutate: vi.fn() }),
}))

describe('AITriageButton', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    hasModule = true
    role = 'member'
    config = { isEnabled: true }
  })

  it('renders nothing when the module is off', () => {
    hasModule = false
    const { container } = render(<AITriageButton findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('tells an administrator AI triage is off and links to Settings > AI', async () => {
    role = 'admin'
    config = { isEnabled: false, reason: 'not_enabled' }
    render(<AITriageButton findingId="f1" />)
    const button = screen.getByRole('button', { name: /AI triage/ })
    expect(button).toHaveAttribute('aria-disabled', 'true')
    await userEvent.click(button)
    expect(screen.getByText(/Turn it on in Settings > AI/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Open Settings > AI/ })).toHaveAttribute(
      'href',
      '/settings/ai'
    )
    expect(trigger).not.toHaveBeenCalled()
  })

  it('tells a member to ask an administrator, without a settings link', async () => {
    config = { isEnabled: false, reason: 'not_enabled' }
    render(<AITriageButton findingId="f1" />)
    await userEvent.click(screen.getByRole('button', { name: /AI triage/ }))
    expect(screen.getByText(/Ask an organization administrator/)).toBeInTheDocument()
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.queryByText(/permission/i)).toBeNull()
  })

  it('says the platform has no AI provider, never "no permission"', async () => {
    role = 'owner'
    config = { isEnabled: false, reason: 'platform_not_configured' }
    render(<AITriageButton findingId="f1" />)
    await userEvent.click(screen.getByRole('button', { name: /AI triage/ }))
    expect(screen.getByText(/A platform administrator sets up the AI provider/)).toBeInTheDocument()
    expect(screen.queryByRole('link')).toBeNull()
  })

  it('says the monthly allowance is used up', async () => {
    config = { isEnabled: false, reason: 'budget_exhausted' }
    render(<AITriageButton findingId="f1" />)
    await userEvent.click(screen.getByRole('button', { name: /AI triage/ }))
    expect(screen.getByText(/monthly AI allowance/)).toBeInTheDocument()
  })

  it('starts an analysis when AI is available', async () => {
    trigger.mockResolvedValue({ jobId: 'j1', status: 'pending' })
    render(<AITriageButton findingId="f1" />)
    await userEvent.click(screen.getByRole('button', { name: /AI triage/ }))
    await waitFor(() => expect(trigger).toHaveBeenCalledWith({ mode: 'quick' }))
  })

  it('explains a refusal by the AI data policy and refreshes availability on AI_DISABLED', async () => {
    trigger.mockRejectedValueOnce(new ApiClientError('raw', 'AI_POLICY_RESTRICTED', 403))
    render(<AITriageButton findingId="f1" />)
    await userEvent.click(screen.getByRole('button', { name: /AI triage/ }))
    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith(
        'AI analysis did not start',
        expect.objectContaining({ description: expect.stringMatching(/AI data policy/) })
      )
    )
    expect(mutateConfig).not.toHaveBeenCalled()

    trigger.mockRejectedValueOnce(new ApiClientError('raw', 'AI_DISABLED', 403))
    await userEvent.click(screen.getByRole('button', { name: /AI triage/ }))
    await waitFor(() => expect(mutateConfig).toHaveBeenCalled())
    // The server's own text is never shown.
    for (const call of toastError.mock.calls) {
      expect(JSON.stringify(call)).not.toContain('raw')
    }
  })
})
