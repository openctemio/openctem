/**
 * Approving scope changes asks first: a single change names its pattern, a
 * selection names the count and lists the patterns, and nothing is sent
 * before the confirmation.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: () => true,
    usePermissions: () => ({ can: () => true, isOwner: () => false }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u-me' }) }))
vi.mock('../scope-attestations', () => ({ ScopeAttestations: () => null }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))

const { ScopeApprovals } = await import('../scope-approvals')

const entry = (id: string, pattern: string) => ({
  id,
  pattern,
  target_type: 'domain',
  status: 'pending',
  max_tier: 't1',
  created_by: { id: 'u-other', name: 'Other' },
  created_at: `2026-10-0${id.slice(1)}T00:00:00Z`,
  approvals: [],
  approvals_required: 1,
})

beforeEach(() => {
  api.post.mockReset().mockResolvedValue({})
  api.get.mockReset().mockImplementation((url: string) => {
    if (url.includes('/scope/targets'))
      return Promise.resolve({
        data: [entry('e1', 'a.example.com'), entry('e2', 'b.example.com')],
        total: 2,
      })
    if (url.includes('/scope/exclusions')) return Promise.resolve({ data: [], total: 0 })
    return Promise.resolve({})
  })
})

const wrap = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <ScopeApprovals />
    </SWRConfig>
  )

describe('scope approvals confirmation', () => {
  it('a single Approve names the pattern and sends nothing until confirmed', async () => {
    wrap()
    const buttons = await screen.findAllByRole('button', { name: 'Approve' })
    await userEvent.click(buttons[0])
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Approve the change to a.example.com?')
    expect(api.post).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve change' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
  })

  it('Approve selected counts the changes and lists them', async () => {
    wrap()
    await userEvent.click(await screen.findByRole('checkbox', { name: /select every change/i }))
    await userEvent.click(screen.getByRole('button', { name: 'Approve selected (2)' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Approve 2 scope changes?')
    expect(within(dialog).getByText('a.example.com')).toBeInTheDocument()
    expect(within(dialog).getByText('b.example.com')).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve 2 changes' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(2))
  })
})
