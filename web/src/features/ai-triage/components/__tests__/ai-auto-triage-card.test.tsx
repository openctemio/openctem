import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AIAutoTriageCard } from '../ai-auto-triage-card'
import { autoTriageWidens } from '../../api/use-ai-auto-triage'

let policy = { enabled: false, severities: ['critical', 'high'], delay_seconds: 60 }
const update = vi.fn()
const mutate = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/ai-triage/api/use-ai-auto-triage', async (orig) => ({
  ...(await orig<typeof import('@/features/ai-triage/api/use-ai-auto-triage')>()),
  useAIAutoTriage: () => ({ data: policy, isLoading: false, error: undefined, mutate }),
  updateAIAutoTriage: (...a: unknown[]) => update(...a),
}))

describe('AIAutoTriageCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    policy = { enabled: false, severities: ['critical', 'high'], delay_seconds: 60 }
  })

  it('asks before turning automatic triage on, then saves', async () => {
    update.mockResolvedValue({ ...policy, enabled: true, loosened: true })
    render(<AIAutoTriageCard canEdit aiEnabled />)
    await userEvent.click(screen.getByRole('switch', { name: /Triage new findings automatically/ }))
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    expect(update).not.toHaveBeenCalled()
    expect(await screen.findByText('Send more findings automatically?')).toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: 'Save' }).at(-1)!)
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({
        enabled: true,
        severities: ['critical', 'high'],
        delay_seconds: 60,
      })
    )
  })

  it('turns it off without a confirmation', async () => {
    policy = { enabled: true, severities: ['critical'], delay_seconds: 60 }
    update.mockResolvedValue({ ...policy, enabled: false })
    render(<AIAutoTriageCard canEdit aiEnabled />)
    await userEvent.click(screen.getByRole('switch', { name: /Triage new findings automatically/ }))
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith(expect.objectContaining({ enabled: false }))
    )
    expect(screen.queryByText('Send more findings automatically?')).not.toBeInTheDocument()
  })

  it('is read only without the permission and says when AI triage is off', () => {
    render(<AIAutoTriageCard canEdit={false} aiEnabled={false} />)
    expect(screen.getByRole('switch', { name: /Triage new findings automatically/ })).toBeDisabled()
    expect(screen.getByText(/AI triage is off/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Save/ })).not.toBeInTheDocument()
  })

  it('classifies widening like the API', () => {
    const p = (enabled: boolean, ...severities: ('critical' | 'high' | 'low')[]) => ({
      enabled,
      severities,
      delay_seconds: 0,
    })
    expect(autoTriageWidens(p(false, 'critical'), p(true, 'critical'))).toBe(true)
    expect(autoTriageWidens(p(true, 'critical'), p(true, 'critical', 'low'))).toBe(true)
    expect(autoTriageWidens(p(true, 'critical', 'low'), p(true, 'critical'))).toBe(false)
    expect(autoTriageWidens(p(true, 'critical'), p(false, 'critical', 'high'))).toBe(false)
  })
})
