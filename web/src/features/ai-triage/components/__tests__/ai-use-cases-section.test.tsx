import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AIUseCasesSection } from '../ai-use-cases-section'
import {
  widensUseCase,
  validMinConfidence,
  type AIUseCaseSetting,
} from '../../api/use-ai-use-cases'

function setting(over: Partial<AIUseCaseSetting> = {}): AIUseCaseSetting {
  return {
    use_case: 'triage',
    mode: 'suggest',
    effective_mode: 'suggest',
    ceiling: 'internal',
    min_confidence: 0.85,
    ...over,
  }
}

let items: AIUseCaseSetting[] = []
const update = vi.fn()
const mutate = vi.fn()

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/ai-triage/api/use-ai-use-cases', async (orig) => ({
  ...(await orig<typeof import('@/features/ai-triage/api/use-ai-use-cases')>()),
  useAIUseCases: () => ({ data: { items }, isLoading: false, error: undefined, mutate }),
  updateAIUseCase: (...a: unknown[]) => update(...a),
}))

function row(name: string) {
  return screen.getByTestId(`ai-use-case-${name}`)
}

describe('AIUseCasesSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    items = [
      setting(),
      setting({ use_case: 'remediation', effective_mode: 'suggest' }),
      setting({ use_case: 'summary' }),
    ]
  })

  it('lists the three use cases with their defaults', () => {
    render(<AIUseCasesSection canEdit aiEnabled />)
    for (const name of ['Triage', 'Remediation steps', 'Summary']) {
      expect(screen.getByText(name)).toBeInTheDocument()
    }
    const triage = within(row('triage'))
    expect(triage.getByRole('radio', { name: 'Suggest' })).toHaveAttribute('aria-checked', 'true')
    // The minimum confidence matters only in auto-apply.
    expect(triage.getByLabelText('Minimum confidence to auto-apply')).toBeDisabled()
  })

  it('asks before turning auto-apply on, then saves only that use case', async () => {
    update.mockResolvedValue(setting({ mode: 'auto_apply', loosened: ['auto_apply_on'] }))
    render(<AIUseCasesSection canEdit aiEnabled />)
    await userEvent.click(within(row('triage')).getByRole('radio', { name: 'Auto-apply' }))
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    expect(update).not.toHaveBeenCalled()
    expect(await screen.findByText('Let AI do more?')).toBeInTheDocument()
    await userEvent.click(screen.getAllByRole('button', { name: 'Save' }).at(-1)!)
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith('triage', {
        mode: 'auto_apply',
        ceiling: 'internal',
        min_confidence: 0.85,
      })
    )
    expect(update).toHaveBeenCalledTimes(1)
  })

  it('turns a use case off without a confirmation', async () => {
    items[0] = setting({ mode: 'auto_apply', effective_mode: 'auto_apply' })
    update.mockResolvedValue(setting({ mode: 'off' }))
    render(<AIUseCasesSection canEdit aiEnabled />)
    await userEvent.click(within(row('triage')).getByRole('radio', { name: 'Off' }))
    await userEvent.click(screen.getByRole('button', { name: /^Save/ }))
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith('triage', expect.objectContaining({ mode: 'off' }))
    )
    expect(screen.queryByText('Let AI do more?')).not.toBeInTheDocument()
  })

  it('shows an automatic downgrade and offers to turn auto-apply back on', async () => {
    items[0] = setting({
      mode: 'suggest',
      downgrade: {
        at: new Date().toISOString(),
        reason: 'override_rate',
        decisions: 12,
        overrides: 3,
      },
    })
    render(<AIUseCasesSection canEdit aiEnabled />)
    expect(screen.getByText('Moved back to Suggest')).toBeInTheDocument()
    expect(screen.getByText(/overrode 3 of its last 12 results/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Turn auto-apply back on' }))
    expect(within(row('triage')).getByRole('radio', { name: 'Auto-apply' })).toHaveAttribute(
      'aria-checked',
      'true'
    )
  })

  it('is read only without the permission and says when AI is off', () => {
    render(<AIUseCasesSection canEdit={false} aiEnabled={false} />)
    expect(within(row('triage')).getByRole('radio', { name: 'Auto-apply' })).toBeDisabled()
    expect(screen.getByText(/AI is off for this organization/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Save/ })).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Turn auto-apply back on' })
    ).not.toBeInTheDocument()
  })
})

describe('widensUseCase', () => {
  const base = { mode: 'suggest' as const, ceiling: 'internal' as const, min_confidence: 0.85 }
  it('matches the API loosening rules', () => {
    expect(widensUseCase(base, { ...base, mode: 'auto_apply' })).toBe(true)
    expect(widensUseCase(base, { ...base, ceiling: 'restricted' })).toBe(true)
    expect(widensUseCase({ ...base, ceiling: 'public' }, base)).toBe(false)
    const auto = { ...base, mode: 'auto_apply' as const }
    expect(widensUseCase(auto, { ...auto, min_confidence: 0.6 })).toBe(true)
    expect(widensUseCase(auto, { ...auto, mode: 'off' })).toBe(false)
    expect(widensUseCase(base, { ...base, min_confidence: 0.5 })).toBe(false)
  })
  it('bounds the minimum confidence', () => {
    expect(validMinConfidence(0.5)).toBe(true)
    expect(validMinConfidence(0.99)).toBe(true)
    expect(validMinConfidence(0.49)).toBe(false)
    expect(validMinConfidence(1)).toBe(false)
    expect(validMinConfidence(Number.NaN)).toBe(false)
  })
})
