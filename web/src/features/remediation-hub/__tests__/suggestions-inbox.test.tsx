/**
 * The suggestions inbox reviews with the keyboard: j/k move, a accepts the
 * active suggestion (at its version), d opens the dismiss dialog, and keys
 * typed in a field do nothing.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { RemediationSuggestion } from '../api/types'
import { ApiClientError } from '@/lib/api/error-handler'

const approve = vi.fn()
// Permissions the mocked member holds; the default is everything.
const granted = { write: true }
const items = { join: false }
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
  usePermissions: () => ({
    hasPermission: (p: string) => granted.write || !p.endsWith(':write'),
  }),
}))
const replace = vi.fn()
const search = { value: '' }
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace }),
  useSearchParams: () => new URLSearchParams(search.value),
}))
vi.mock('../api/use-owner-names', () => ({
  useOwnerNames: () => ({ users: [], groups: [], user: () => undefined, group: () => undefined }),
}))
vi.mock('../api/use-remediation-hub', () => ({
  useSuggestions: () => ({
    data: {
      data: [
        suggestion('one', 'First fix'),
        items.join
          ? { ...suggestion('two', 'Second fix'), kind: 'join', target_task_id: 't1' }
          : suggestion('two', 'Second fix'),
      ],
      total: 2,
      page: 1,
      per_page: 25,
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useSuggestionMembers: () => ({ data: undefined }),
  useSuggestion: () => ({ data: undefined, isLoading: false }),
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
    granted.write = true
    items.join = false
    approve.mockReset()
    replace.mockReset()
    search.value = ''
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

  it('offers an asset owner without write access only "Accept as owner" on a join', async () => {
    granted.write = false
    items.join = true
    render(<SuggestionsInbox />)
    const buttons = screen.getAllByRole('button', { name: 'Accept as owner' })
    expect(buttons).toHaveLength(1)
    expect(screen.queryByRole('button', { name: 'Accept' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Dismiss' })).not.toBeInTheDocument()
    expect(screen.getByText(/a accept as owner/)).toBeInTheDocument()
    // The keyboard follows the same rule: a on the new fix does nothing, on the join it accepts.
    const user = userEvent.setup()
    await user.keyboard('a')
    expect(approve).not.toHaveBeenCalled()
    await user.keyboard('j')
    await user.keyboard('a')
    await waitFor(() => expect(approve).toHaveBeenCalledWith('two', { version: 7 }))
  })

  it('opens the detail panel of the active suggestion with Enter (a deep link)', async () => {
    render(<SuggestionsInbox />)
    const user = userEvent.setup()
    await user.keyboard('j')
    await user.keyboard('{Enter}')
    expect(replace).toHaveBeenCalledWith('?suggestion=two', { scroll: false })
  })

  it('asks what to do with findings another task took, then skips them by default', async () => {
    approve.mockRejectedValueOnce(
      new ApiClientError(
        '2 finding(s) already belong to another remediation task',
        'FINDINGS_IN_OTHER_TASK',
        409,
        {
          conflicts: [
            {
              finding_id: 'f1',
              finding_title: 'SQL injection in /login',
              task_id: 't9',
              task_title: 'Patch the gateway',
              assignee_user_id: null,
              assignee_group_id: null,
              can_move: true,
            },
            {
              finding_id: 'f2',
              finding_title: 'Old jquery',
              task_id: 't8',
              task_title: null,
              assignee_user_id: null,
              assignee_group_id: null,
              can_move: false,
            },
          ],
        }
      )
    )
    render(<SuggestionsInbox />)
    const user = userEvent.setup()
    await user.keyboard('a')
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('Some findings are already in another task')
    expect(dialog).toHaveTextContent('In task "Patch the gateway" (Unassigned)')
    // A task the person cannot read is not named.
    expect(dialog).toHaveTextContent('In another task')
    expect(screen.getAllByRole('radio', { name: 'Move here' })[1]).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Skip them and accept' }))
    await waitFor(() =>
      expect(approve).toHaveBeenLastCalledWith('one', { version: 7, conflicts: { skip: true } })
    )
  })

  it('moves a finding only with a reason', async () => {
    approve.mockRejectedValueOnce(
      new ApiClientError('conflict', 'FINDINGS_IN_OTHER_TASK', 409, {
        conflicts: [
          {
            finding_id: 'f1',
            finding_title: 'SQL injection in /login',
            task_id: 't9',
            task_title: 'Patch the gateway',
            assignee_user_id: null,
            assignee_group_id: null,
            can_move: true,
          },
        ],
      })
    )
    render(<SuggestionsInbox />)
    const user = userEvent.setup()
    await user.keyboard('a')
    await screen.findByRole('dialog')
    await user.click(screen.getByRole('radio', { name: 'Move here' }))
    const confirm = screen.getByRole('button', { name: 'Move 1 and accept' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: 'Why move them' }), 'Same upgrade')
    await user.click(confirm)
    await waitFor(() =>
      expect(approve).toHaveBeenLastCalledWith('one', {
        version: 7,
        conflicts: { move: ['f1'], move_reason: 'Same upgrade' },
      })
    )
  })
})
