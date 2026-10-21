import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AssigneeSelect } from '../assignee-select'

const assignable = vi.fn()
const members = vi.fn()
vi.mock('../../api/use-assignable-members', () => ({
  useAssignableMembers: (...args: unknown[]) => assignable(...args),
}))
vi.mock('@/features/organization/api/use-members', () => ({
  useMembers: (...args: unknown[]) => members(...args),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-1' } }),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback?: string, vars?: Record<string, unknown>) =>
      (fallback ?? _k).replace(/\{(\w+)\}/g, (_m, k) => String(vars?.[k] ?? '')),
  }),
}))

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  )
  Element.prototype.scrollIntoView = vi.fn()
  assignable.mockReset()
  members.mockReset()
  members.mockReturnValue({
    members: [{ user_id: 'u-all', name: 'Every Member', email: 'e@x.test' }],
    total: 1,
    isLoading: false,
  })
  assignable.mockReturnValue({
    members: [{ user_id: 'u-ok', name: 'Readable Person', role: 'member' }],
    isLoading: false,
  })
})

describe('AssigneeSelect', () => {
  it('lists only the members the server says can read the finding', async () => {
    render(<AssigneeSelect findingId="f-1" onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    expect(screen.getByText('Readable Person')).toBeInTheDocument()
    expect(screen.queryByText('Every Member')).not.toBeInTheDocument()
    // The plain member list is not requested for a single finding.
    expect(members.mock.calls.every(([tenant]) => tenant === undefined)).toBe(true)
    expect(assignable).toHaveBeenLastCalledWith('f-1', expect.objectContaining({ enabled: true }))
  })

  it('without a finding (bulk) keeps the member list and does not ask the finding endpoint', async () => {
    assignable.mockReturnValue({ members: [], isLoading: false })
    render(<AssigneeSelect onChange={vi.fn()} />)
    await userEvent.click(screen.getByRole('button'))
    expect(screen.getByText('Every Member')).toBeInTheDocument()
    expect(assignable).toHaveBeenLastCalledWith(undefined, expect.anything())
  })

  it('passes the chosen member to onChange', async () => {
    const onChange = vi.fn()
    render(<AssigneeSelect findingId="f-1" onChange={onChange} />)
    await userEvent.click(screen.getByRole('button'))
    await userEvent.click(screen.getByText('Readable Person'))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'u-ok', name: 'Readable Person' })
    )
  })
})
