import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'

import { ApiClientError } from '@/lib/api/error-handler'
import { AISuggestionsPanel } from '../ai-suggestions-panel'

const get = vi.fn()
let perms: string[] = ['findings:read', 'ai_triage:read', 'findings:write']

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  get: (...a: unknown[]) => get(...a),
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissionsSafe: () => ({ hasPermission: (p: string) => perms.includes(p) }),
}))

function renderPanel() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AISuggestionsPanel findingId="f1" />
    </SWRConfig>
  )
}

const base = {
  run_id: 'r1',
  use_case: 'triage',
  subject_type: 'finding',
  subject_id: 'f1',
  direction: 'additive',
  evidence: [],
  review_reasons: [],
  created_at: '2026-10-28T00:00:00Z',
  origin: 'ai',
  run: { executor: 'builtin' },
}

describe('AISuggestionsPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms = ['findings:read', 'ai_triage:read', 'findings:write']
  })

  it('renders nothing when the API has no AI suggestions route yet (404)', async () => {
    get.mockRejectedValue(new ApiClientError('Not Found', 'NOT_FOUND', 404))
    const { container } = renderPanel()
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/findings/f1/ai/suggestions'))
    expect(container).toBeEmptyDOMElement()
  })

  it('sends no request without ai_triage:read', () => {
    perms = ['findings:read']
    const { container } = renderPanel()
    expect(get).not.toHaveBeenCalled()
    expect(container).toBeEmptyDOMElement()
  })

  it('groups open and applied suggestions by kind and hides decided ones', async () => {
    get.mockResolvedValue({
      data: [
        { ...base, id: 'a', kind: 'summary', payload: { text: 'Sum' }, state: 'open' },
        {
          ...base,
          id: 'b',
          kind: 'verdict',
          payload: { verdict: 'true_positive', reason: 'Real' },
          state: 'applied',
        },
        { ...base, id: 'c', kind: 'summary', payload: { text: 'Old' }, state: 'dismissed' },
      ],
    })
    renderPanel()
    expect(await screen.findByText('AI suggestions')).toBeInTheDocument()
    const cards = screen.getAllByTestId('ai-suggestion-card')
    expect(cards).toHaveLength(2)
    // Verdict first, then summary.
    expect(cards[0]).toHaveAttribute('data-state', 'applied')
    expect(cards[1]).toHaveAttribute('data-state', 'open')
    expect(screen.queryByText('Old')).toBeNull()
    expect(screen.getAllByTestId('ai-badge')).toHaveLength(2)
  })
})
