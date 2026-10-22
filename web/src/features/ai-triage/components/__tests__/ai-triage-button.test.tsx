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
let perms: string[] = []
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
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: (p: string) => perms.includes(p) }),
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
    perms = ['ai_triage:read', 'ai_triage:trigger']
    config = { isEnabled: true }
  })

  it('renders nothing when the module is off', () => {
    hasModule = false
    const { container } = render(<AITriageButton findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it.each([
    ['not opted in', { isEnabled: false, reason: 'not_enabled' as const }],
    ['no platform provider', { isEnabled: false, reason: 'platform_not_configured' as const }],
    ['allowance used up', { isEnabled: false, reason: 'budget_exhausted' as const }],
  ])('renders nothing when the organization cannot use AI triage (%s)', (_n, cfg) => {
    config = cfg
    const { container } = render(<AITriageButton findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing without the ai_triage:trigger permission', () => {
    perms = ['ai_triage:read']
    const { container } = render(<AITriageButton findingId="f1" />)
    expect(container).toBeEmptyDOMElement()
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
