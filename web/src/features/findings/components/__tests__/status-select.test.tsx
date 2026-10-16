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
    expect(onChange).toHaveBeenCalledWith('in_progress')
    expect(onChange).not.toHaveBeenCalledWith('resolved')
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
})
