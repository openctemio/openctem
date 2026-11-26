import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AIAutonomyCard } from '../ai-autonomy-card'
import { loosensAutonomy, validLimit, type AIAutonomy } from '../../api/use-ai-autonomy'

let data: AIAutonomy = { paused: false, per_hour: 100, per_day: 500 }
const update = vi.fn()
const mutate = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/ai-triage/api/use-ai-autonomy', async (orig) => ({
  ...(await orig<typeof import('@/features/ai-triage/api/use-ai-autonomy')>()),
  useAIAutonomy: () => ({ data, isLoading: false, error: undefined, mutate }),
  updateAIAutonomy: (...a: unknown[]) => update(...a),
}))

describe('loosensAutonomy', () => {
  const base = { paused: false, per_hour: 100, per_day: 500 }
  it('treats resume, a higher limit and unlimited as loosening', () => {
    expect(loosensAutonomy({ ...base, paused: true }, base)).toBe(true)
    expect(loosensAutonomy(base, { ...base, per_hour: 101 })).toBe(true)
    expect(loosensAutonomy(base, { ...base, per_day: null })).toBe(true)
  })
  it('treats pause and a lower limit as tightening', () => {
    expect(loosensAutonomy(base, { ...base, paused: true })).toBe(false)
    expect(loosensAutonomy(base, { ...base, per_hour: 0 })).toBe(false)
    expect(loosensAutonomy({ ...base, per_day: null }, { ...base, per_day: 10 })).toBe(false)
  })
  it('validates limits', () => {
    expect(validLimit(null)).toBe(true)
    expect(validLimit(0)).toBe(true)
    expect(validLimit(100000)).toBe(true)
    expect(validLimit(-1)).toBe(false)
    expect(validLimit(1.5)).toBe(false)
    expect(validLimit(Number.NaN)).toBe(false)
  })
})

describe('AIAutonomyCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    data = { paused: false, per_hour: 100, per_day: 500 }
    update.mockImplementation(async (input) => ({ ...input }))
  })

  it('pauses in one click without asking', async () => {
    render(<AIAutonomyCard canEdit />)
    await userEvent.click(screen.getByRole('button', { name: 'Pause now' }))
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({ paused: true, per_hour: 100, per_day: 500 })
    )
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })

  it('asks before resuming', async () => {
    data = { paused: true, per_hour: 100, per_day: 500 }
    render(<AIAutonomyCard canEdit />)
    expect(screen.getByRole('status')).toHaveTextContent('Paused: AI agents only suggest')
    await userEvent.click(screen.getByRole('button', { name: 'Resume' }))
    expect(update).not.toHaveBeenCalled()
    expect(
      await screen.findByText('Let AI agents change more without a person?')
    ).toBeInTheDocument()
  })

  it('shows no controls to a reader', () => {
    render(<AIAutonomyCard canEdit={false} />)
    expect(screen.queryByRole('button', { name: 'Pause now' })).toBeNull()
    expect(screen.getByLabelText('At most per hour')).toBeDisabled()
  })
})
