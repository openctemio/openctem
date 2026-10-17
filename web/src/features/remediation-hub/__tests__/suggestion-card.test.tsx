/**
 * A suggestion card explains itself, offers the decisions only to a person
 * who may decide, and refuses them while findings are outside the person's
 * access.
 */

import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({ users: [], groups: [], user: () => 'Hoa N.', group: () => undefined }),
}))

import { SuggestionCard } from '../components/suggestion-card'
import type { RemediationSuggestion } from '../api/types'

const base: RemediationSuggestion = {
  id: 's1',
  kind: 'new_group',
  algorithm: 'deterministic',
  algorithm_version: 1,
  action_key: 'upgrade:pypi:django:4.2.30',
  key_kind: 'upgrade',
  title: 'Upgrade django to 4.2.30',
  partitions: [
    { owner_user_id: 'u1', owner_rule: 'asset_owner', finding_ids: ['a', 'b'], risk_points: 6 },
  ],
  member_count: 2,
  hidden_members: 0,
  truncated: 0,
  risk_points: 6,
  risk_parts: { p0: 0, p1: 1, p2: 1, p3: 0, unclassified: 0, kev: 0, assets: 1 },
  has_urgent: false,
  confidence: 1,
  fix_spec: { kind: 'upgrade', ecosystem: 'pypi', package: 'django', target_version: '4.2.30' },
  state: 'proposed',
  version: 1,
  created_at: '2026-10-16T00:00:00Z',
  updated_at: '2026-10-16T00:00:00Z',
}

function renderCard(
  over: Partial<RemediationSuggestion> = {},
  canWrite = true,
  canOwnerAccept = false
) {
  const handlers = { onAccept: vi.fn(), onEdit: vi.fn(), onDismiss: vi.fn(), onSnooze: vi.fn() }
  render(
    <SuggestionCard
      suggestion={{ ...base, ...over }}
      canWrite={canWrite}
      canOwnerAccept={canOwnerAccept}
      {...handlers}
    />
  )
  return handlers
}

describe('SuggestionCard', () => {
  it('shows the fix, its reach, the owner and the risk parts', () => {
    renderCard()
    expect(screen.getByRole('heading', { name: 'Upgrade django to 4.2.30' })).toBeInTheDocument()
    expect(screen.getByText(/2 findings on 1 assets · risk 6/)).toBeInTheDocument()
    expect(screen.getByText(/P1 1 · P2 1/)).toBeInTheDocument()
    expect(screen.getByText(/Hoa N\./)).toBeInTheDocument()
  })

  it('explains why it was grouped, with the command to copy', async () => {
    renderCard()
    await userEvent.setup().click(screen.getByRole('button', { name: /Why\?/ }))
    expect(screen.getByTestId('suggestion-explain')).toHaveTextContent(
      'same package to the same version'
    )
    expect(screen.getByTestId('fix-steps')).toHaveTextContent('pip install "django>=4.2.30"')
  })

  it('accepts on click', async () => {
    const h = renderCard()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Accept' }))
    expect(h.onAccept).toHaveBeenCalled()
  })

  it('refuses decisions while findings are hidden from the person', () => {
    renderCard({ hidden_members: 3 })
    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled()
    expect(screen.getByText(/3 findings are outside your access/)).toBeInTheDocument()
  })

  it('offers no decision without the permission', () => {
    renderCard({}, false)
    expect(screen.queryByRole('button', { name: 'Accept' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Why\?/ })).toBeInTheDocument()
  })

  it('lets an asset owner without write access accept as it is, nothing else', async () => {
    const h = renderCard({ kind: 'join', target_task_id: 't1' }, false, true)
    await userEvent.setup().click(screen.getByRole('button', { name: 'Accept as owner' }))
    expect(h.onAccept).toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Dismiss' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Snooze' })).not.toBeInTheDocument()
  })

  it('shows the full decisions, not the owner button, to a person with write access', () => {
    renderCard({ kind: 'join' }, true, true)
    expect(screen.getByRole('button', { name: 'Accept' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Accept as owner' })).not.toBeInTheDocument()
  })
})
