/**
 * StatusSelect renders the API's moves for this user (its transition
 * engine): an allowed move is offered, a blocked one is disabled with the
 * reason, and a duplicate (the canonical picker) is never a plain status
 * change. The console keeps no copy of the rules.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { StatusSelect } from '../status-select'
import type { FindingTransitions } from '../../api/use-finding-transitions'

// Radix menus measure their trigger; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

let mockData: FindingTransitions | undefined
const requested: (string | null)[] = []
vi.mock('../../api/use-finding-transitions', () => ({
  findingTransitionsKey: (id: string) => `/api/v1/findings/${id}/transitions`,
  useFindingTransitions: (id: string | null) => {
    requested.push(id)
    return { data: id ? mockData : undefined, isLoading: false }
  },
}))

const SUBS = new Map([
  [
    'sub-review',
    {
      id: 'sub-review',
      key: 'in_review',
      canonical_status: 'in_progress',
      name: 'In review',
      labels: { vi: 'Đang xem xét' },
      description: '',
      color: 'blue',
      sort_order: 0,
      archived: false,
      created_at: '',
      updated_at: '',
    },
  ],
])
vi.mock('../../api/use-finding-lifecycles', () => ({
  useSubStatusCatalog: () => SUBS,
  subStatusName: (s: { name: string }) => s.name,
}))

beforeEach(() => {
  requested.length = 0
})

describe('StatusSelect', () => {
  it('asks the API only when the menu opens', async () => {
    mockData = { status: 'fix_applied', transitions: [] }
    render(<StatusSelect findingId="f-1" value="fix_applied" onChange={vi.fn()} />)
    expect(requested.every((id) => id === null)).toBe(true)
    await userEvent.click(screen.getByRole('button'))
    expect(requested).toContain('f-1')
  })

  it('offers the allowed moves and disables a blocked one with its reason', async () => {
    mockData = {
      status: 'fix_applied',
      transitions: [
        {
          to: 'resolved',
          allowed: false,
          mode: 'direct',
          blocked: [{ code: 'missing_permission', params: { permission: 'findings:verify' } }],
        },
        { to: 'in_progress', allowed: true, mode: 'direct' },
      ],
    }
    const onChange = vi.fn()
    render(<StatusSelect findingId="f-1" value="fix_applied" onChange={onChange} />)
    await userEvent.click(screen.getByRole('button'))
    const resolved = screen.getByRole('menuitem', { name: /resolved/i })
    expect(resolved.getAttribute('aria-disabled')).toBe('true')
    await userEvent.click(screen.getByRole('menuitem', { name: /in progress/i }))
    expect(onChange).toHaveBeenCalledWith('in_progress', expect.objectContaining({ allowed: true }))
    expect(onChange).not.toHaveBeenCalledWith('resolved', expect.anything())
  })

  it('never offers Duplicate: it needs the finding it duplicates', async () => {
    mockData = {
      status: 'confirmed',
      transitions: [
        { to: 'in_progress', allowed: true, mode: 'direct' },
        { to: 'duplicate', allowed: true, mode: 'duplicate_picker' },
      ],
    }
    render(<StatusSelect findingId="f-1" value="confirmed" onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    expect(screen.getByRole('menuitem', { name: /in progress/i })).toBeTruthy()
    expect(screen.queryByRole('menuitem', { name: /duplicate/i })).toBeNull()
  })

  it('offers sub-status moves with what each needs, and hands the move to the caller', async () => {
    mockData = {
      status: 'confirmed',
      transitions: [
        { to: 'in_progress', allowed: true, mode: 'direct' },
        {
          to: 'in_progress',
          allowed: true,
          mode: 'direct',
          to_sub_status_id: 'sub-review',
          transition: 'send_to_review',
          name: 'Send to review',
          note_min_len: 20,
          fields: ['ticket_link'],
        },
        {
          to: 'false_positive',
          allowed: true,
          mode: 'request',
          to_sub_status_id: 'sub-review',
        },
      ],
    }
    const onChange = vi.fn()
    render(
      <StatusSelect findingId="f-1" value="confirmed" onChange={onChange} allowSubStatusMoves />
    )
    await userEvent.click(screen.getByRole('button'))
    const item = screen.getByRole('menuitem', { name: /send to review/i })
    expect(item).toHaveTextContent(/note of 20\+ characters/i)
    expect(item).toHaveTextContent(/ticket link/i)
    // A request carries no sub-status yet: only its status move is offered.
    expect(screen.getAllByRole('menuitem')).toHaveLength(2)
    await userEvent.click(item)
    expect(onChange).toHaveBeenCalledWith(
      'in_progress',
      expect.objectContaining({ to_sub_status_id: 'sub-review', fields: ['ticket_link'] })
    )
  })

  it('offers only status moves where the caller cannot send a sub-status', async () => {
    mockData = {
      status: 'confirmed',
      transitions: [
        { to: 'in_progress', allowed: true, mode: 'direct' },
        { to: 'in_progress', allowed: true, mode: 'direct', to_sub_status_id: 'sub-review' },
      ],
    }
    render(<StatusSelect findingId="f-1" value="confirmed" onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    expect(screen.getAllByRole('menuitem')).toHaveLength(1)
  })

  it('shows the current sub-status next to the status', () => {
    mockData = { status: 'in_progress', transitions: [] }
    render(
      <StatusSelect
        findingId="f-1"
        value="in_progress"
        subStatusId="sub-review"
        onChange={vi.fn()}
      />
    )
    expect(screen.getByText('In review')).toBeInTheDocument()
  })
})
