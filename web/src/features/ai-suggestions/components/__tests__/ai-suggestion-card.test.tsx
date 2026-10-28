import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'sonner'

import { ApiClientError } from '@/lib/api/error-handler'
import type { AISuggestion } from '../../api/ai-governance-api'
import { AI_TEXT_COLLAPSED } from '../../lib/ai-model-text'
import { AISuggestionCard } from '../ai-suggestion-card'

const apply = vi.fn()
const dismiss = vi.fn()
const undo = vi.fn()
let perms: string[] = ['findings:write', 'findings:severity']

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: (p: string) => perms.includes(p) }),
}))
vi.mock('../../api/ai-governance-api', async (orig) => ({
  ...(await orig<typeof import('../../api/ai-governance-api')>()),
  applyAISuggestion: (...a: unknown[]) => apply(...a),
  dismissAISuggestion: (...a: unknown[]) => dismiss(...a),
  undoAISuggestion: (...a: unknown[]) => undo(...a),
}))

function suggestion(over: Partial<AISuggestion> = {}): AISuggestion {
  return {
    id: 's1',
    run_id: 'r1',
    use_case: 'triage',
    subject_type: 'finding',
    subject_id: 'f1',
    kind: 'summary',
    payload: { text: 'A short summary.' },
    direction: 'additive',
    confidence: 0.82,
    evidence: [],
    state: 'open',
    review_reasons: [],
    created_at: '2026-10-28T00:00:00Z',
    origin: 'ai',
    run: { executor: 'builtin', provider: 'claude', model: 'm' },
    ...over,
  }
}

function renderCard(s: AISuggestion) {
  const onChanged = vi.fn()
  const onWhy = vi.fn()
  render(<AISuggestionCard suggestion={s} onChanged={onChanged} onWhy={onWhy} />)
  return { onChanged, onWhy }
}

describe('AISuggestionCard', () => {
  beforeAll(() => {
    // Radix Select scrolls the selected option into view, which jsdom lacks.
    Element.prototype.scrollIntoView ??= () => {}
  })

  beforeEach(() => {
    vi.clearAllMocks()
    perms = ['findings:write', 'findings:severity']
  })

  it('always carries the shared AI badge, with the source from the executor', () => {
    renderCard(suggestion({ run: { executor: 'tenant_worker' } }))
    const badge = screen.getByTestId('ai-badge')
    expect(badge).toHaveAttribute('data-source', 'ai_analyst')
    expect(badge).toHaveTextContent('Suggested by AI analyst')
    expect(screen.getByText('Confidence 82%')).toBeInTheDocument()
    expect(screen.getByText('Adds information')).toBeInTheDocument()
  })

  it('renders hostile model text as plain text: no element, no link, no markdown', () => {
    const hostile = '<img src=x onerror=alert(1)> [click me](javascript:alert(1)) **bold**'
    const { container } = render(
      <AISuggestionCard
        suggestion={suggestion({
          kind: 'verdict',
          payload: { verdict: 'true_positive', reason: hostile },
          evidence: [{ ref: 'finding.description', quote: '<script>alert(2)</script>' }],
        })}
        onChanged={vi.fn()}
        onWhy={vi.fn()}
      />
    )
    const card = screen.getByTestId('ai-suggestion-card')
    expect(card.querySelector('img')).toBeNull()
    expect(card.querySelector('script')).toBeNull()
    expect(card.querySelector('a')).toBeNull()
    expect(card.querySelector('strong')).toBeNull()
    expect(container.innerHTML).not.toContain('<img')
    expect(screen.getByText(hostile)).toBeInTheDocument()
  })

  it('caps long model text and expands it on request', async () => {
    const long = 'x'.repeat(AI_TEXT_COLLAPSED + 200)
    renderCard(suggestion({ payload: { text: long } }))
    const text = screen.getByTestId('ai-model-text')
    expect(text.textContent!.length).toBeLessThan(long.length)
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }))
    expect(screen.getByTestId('ai-model-text').textContent).toBe(long)
  })

  it('applies an additive suggestion after confirmation', async () => {
    apply.mockResolvedValue({
      suggestion: suggestion({ state: 'applied' }),
      pending_approval: false,
    })
    const { onChanged } = renderCard(suggestion())
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    expect(apply).not.toHaveBeenCalled()
    const dialog = screen.getByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Apply' }))
    await waitFor(() => expect(apply).toHaveBeenCalledWith('s1', undefined))
    expect(onChanged).toHaveBeenCalled()
    expect(toast.success).toHaveBeenCalledWith('Suggestion applied')
  })

  it('needs a closure reason before a false-positive verdict opens an approval request', async () => {
    apply.mockResolvedValue({
      suggestion: suggestion({ state: 'pending_approval' }),
      pending_approval: true,
    })
    renderCard(
      suggestion({
        kind: 'verdict',
        direction: 'lowers_risk',
        payload: { verdict: 'likely_false_positive', reason: 'Test code.' },
      })
    )
    expect(screen.getByText('Lowers risk: needs approval')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Request approval' }))
    const dialog = screen.getByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Request approval' })
    expect(confirm).toBeDisabled()
    await userEvent.click(within(dialog).getByLabelText('Why is it a false positive?'))
    await userEvent.click(screen.getByRole('option', { name: 'Test or example code' }))
    expect(confirm).toBeEnabled()
    await userEvent.click(confirm)
    await waitFor(() => expect(apply).toHaveBeenCalledWith('s1', 'test_or_example_code'))
    expect(toast.success).toHaveBeenCalledWith('Approval requested. Another person decides it.')
  })

  it('dismisses after confirmation', async () => {
    dismiss.mockResolvedValue({
      suggestion: suggestion({ state: 'dismissed' }),
      pending_approval: false,
    })
    renderCard(suggestion())
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    await userEvent.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Dismiss' })
    )
    await waitFor(() => expect(dismiss).toHaveBeenCalledWith('s1'))
  })

  it('offers Undo on an applied suggestion and explains a conflict', async () => {
    undo.mockRejectedValue(new ApiClientError('conflict', 'AI_UNDO_CONFLICT', 409))
    const { onChanged } = renderCard(suggestion({ state: 'auto_applied' }))
    expect(screen.queryByRole('button', { name: 'Apply' })).toBeNull()
    expect(screen.getByText('Applied by policy')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Undo' }))
    await userEvent.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Undo' })
    )
    await waitFor(() => expect(undo).toHaveBeenCalledWith('s1'))
    expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/Change it by hand/))
    expect(onChanged).not.toHaveBeenCalled()
  })

  it('refreshes when someone else already decided it', async () => {
    apply.mockRejectedValue(new ApiClientError('decided', 'AI_SUGGESTION_DECIDED', 409))
    const { onChanged } = renderCard(suggestion())
    await userEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await userEvent.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Apply' })
    )
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(toast.error).toHaveBeenCalledWith(expect.stringMatching(/already decided/))
  })

  it('links a pending approval and offers no decision', () => {
    renderCard(
      suggestion({ state: 'pending_approval', direction: 'lowers_risk', approval_id: 'a1' })
    )
    expect(screen.getByRole('link', { name: 'View the approval request' })).toHaveAttribute(
      'href',
      '/findings/approvals'
    )
    expect(screen.queryByRole('button', { name: /Apply|Request approval|Undo/ })).toBeNull()
  })

  it('hides actions without the permission the change needs, and opens Why for anyone', async () => {
    perms = ['findings:write']
    const { onWhy } = renderCard(
      suggestion({ kind: 'severity', direction: 'raises_risk', payload: { severity: 'high' } })
    )
    expect(screen.queryByRole('button', { name: 'Apply' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Why?' }))
    expect(onWhy).toHaveBeenCalledWith('r1')
  })

  it('lists review reasons for a suggestion that needs review', () => {
    renderCard(suggestion({ state: 'needs_review', review_reasons: ['injection_suspected'] }))
    expect(screen.getByText('The input looks like it tries to steer the AI')).toBeInTheDocument()
  })
})
