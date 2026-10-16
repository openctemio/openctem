/**
 * The suggestions inbox reviews with the keyboard: j/k move, a accepts the
 * active suggestion (at its version), d opens the dismiss dialog, and keys
 * typed in a field do nothing.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { RemediationSuggestion } from '../api/types'

const approve = vi.fn()
const suggestion = (id: string, title: string): RemediationSuggestion => ({
  id,
  kind: 'new_group',
  algorithm: 'deterministic',
  algorithm_version: 1,
  action_key: `upgrade:npm:${id}:1.0.0`,
  key_kind: 'upgrade',
  title,
  partitions: [],
  member_count: 2,
  hidden_members: 0,
  truncated: 0,
  risk_points: 4,
  risk_parts: { p0: 0, p1: 0, p2: 2, p3: 0, unclassified: 0, kev: 0, assets: 1 },
  has_urgent: false,
  confidence: 1,
  fix_spec: {},
  state: 'proposed',
  version: 7,
  created_at: '',
  updated_at: '',
})

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({ users: [], groups: [], user: () => undefined, group: () => undefined }),
}))
vi.mock('../api/use-remediation-hub', () => ({
  useSuggestions: () => ({
    data: {
      data: [suggestion('one', 'First fix'), suggestion('two', 'Second fix')],
      total: 2,
      page: 1,
      per_page: 25,
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useSuggestionMembers: () => ({ data: undefined }),
  useRevalidateHub: () => vi.fn(),
  hubApi: {
    approve: (...a: unknown[]) => approve(...a),
    reject: vi.fn(),
    snooze: vi.fn(),
    reopen: vi.fn(),
    bulkApprove: vi.fn(),
    runNow: vi.fn(),
  },
}))

import { SuggestionsInbox } from '../components/suggestions-inbox'

describe('SuggestionsInbox keyboard review', () => {
  beforeEach(() => {
    approve.mockReset()
    approve.mockResolvedValue({
      suggestion_id: 'two',
      action_id: 'a',
      task_ids: ['t'],
      joined: 0,
      dropped: [],
    })
  })

  it('moves with j and accepts the active suggestion with a', async () => {
    render(<SuggestionsInbox />)
    const user = userEvent.setup()
    await user.keyboard('j')
    await user.keyboard('a')
    await waitFor(() => expect(approve).toHaveBeenCalledWith('two', { version: 7 }))
  })

  it('opens the dismiss dialog with d', async () => {
    render(<SuggestionsInbox />)
    await userEvent.setup().keyboard('d')
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('Dismiss suggestion')
    fireEvent.keyDown(dialog, { key: '4' })
    expect(screen.getByRole('radio', { name: /Wrong owner/ })).toBeChecked()
  })

  it('ignores keys typed in the search field', async () => {
    render(<SuggestionsInbox />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('textbox', { name: 'Search suggestions' }))
    await user.keyboard('a')
    expect(approve).not.toHaveBeenCalled()
  })
})
