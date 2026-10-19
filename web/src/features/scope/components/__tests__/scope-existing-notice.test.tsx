/**
 * Adding an entry or exclusion the organization already has: the dialog says
 * which row it is and what state it is in, with the one action that fits
 * (approve or put in effect a pending one, activate an inactive one, renew
 * an expired entry, remove a rejected one through Show it).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ approve: true, approveExclusions: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) =>
      p === actual.Permission.ScopeApprove
        ? perms.approve
        : p === actual.Permission.ScopeExclusionsApprove
          ? perms.approveExclusions
          : true,
    usePermissions: () => ({ can: () => true, isOwner: () => false }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u-me' }) }))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopeEntryDialog } = await import('../scope-entry-dialog')
const { ScopeExclusionDialog } = await import('../scope-exclusion-dialog')
const { scopeDuplicateOf } = await import('../../lib/scope-codes')

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const baseSettings = {
  one_off_targets: 'admins_and_requests',
  one_off_max_days: 7,
  default_max_tier: 't1',
  effective_widening_approvals: 1,
  admin_count: 2,
  active_proof: 'off',
}
const strict = { ...baseSettings, approval_policy: { entries_need_approval: true } }
const open = { ...baseSettings, approval_policy: { entries_need_approval: false } }

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

function conflict(kind: 'entry' | 'exclusion', status: string) {
  return Object.assign(new Error('this scope entry already exists'), {
    code: kind === 'entry' ? 'SCOPE_ENTRY_EXISTS' : 'SCOPE_EXCLUSION_EXISTS',
    statusCode: 409,
    details: { id: kind === 'entry' ? 'e1' : 'x1', status },
  })
}

function serve(settings: Record<string, unknown>, createdBy = 'someone-else') {
  api.get.mockImplementation(async (url: string) => {
    if (url === '/api/v1/scope/targets/e1')
      return {
        id: 'e1',
        pattern: '*.example.com',
        status: 'pending',
        created_by: { id: createdBy },
        approvals: [],
      }
    if (url.startsWith('/api/v1/easm/verified-domains')) return { data: [] }
    return settings
  })
}

async function addEntry(status: string, settings: Record<string, unknown>, onOpenChange = vi.fn()) {
  serve(settings)
  api.post.mockRejectedValueOnce(conflict('entry', status))
  const user = userEvent.setup()
  wrap(<ScopeEntryDialog open onOpenChange={onOpenChange} />)
  await user.type(await screen.findByLabelText('What'), '*.example.com')
  await user.click(screen.getByRole('button', { name: 'Add to scope' }))
  const notice = await screen.findByTestId('scope-existing')
  return { user, notice, onOpenChange }
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  api.put.mockReset()
  toast.success.mockReset()
  toast.error.mockReset()
  perms.approve = true
  perms.approveExclusions = true
})

describe('scopeDuplicateOf', () => {
  it('reads only a duplicate code with an id and status', () => {
    expect(scopeDuplicateOf(conflict('entry', 'pending'))).toEqual({
      kind: 'entry',
      id: 'e1',
      status: 'pending',
    })
    expect(scopeDuplicateOf({ code: 'SCOPE_ENTRY_EXISTS' })).toBeNull()
    expect(
      scopeDuplicateOf({ code: 'CONFLICT', details: { id: 'e1', status: 'active' } })
    ).toBeNull()
    expect(scopeDuplicateOf(null)).toBeNull()
  })
})

describe('ScopeEntryDialog on a duplicate', () => {
  it('pending, Strict: says it waits for approval; another approver may approve it', async () => {
    const { user, notice, onOpenChange } = await addEntry('pending', strict)
    expect(notice).toHaveTextContent(
      '*.example.com is already in your scope list and is waiting for approval.'
    )
    expect(screen.getByRole('link', { name: 'Open approvals' })).toHaveAttribute(
      'href',
      '/scope?tab=approvals'
    )
    api.post.mockResolvedValueOnce({ id: 'e1', status: 'active' })
    await user.click(await screen.findByRole('button', { name: 'Approve' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/approve', {})
    )
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
  })

  it('pending, Strict: the requester gets no Approve', async () => {
    serve(strict, 'u-me')
    api.post.mockRejectedValueOnce(conflict('entry', 'pending'))
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('What'), '*.example.com')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await screen.findByTestId('scope-existing')
    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/v1/scope/targets/e1'))
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
  })

  it('pending where approvals are no longer required: Put in effect activates it', async () => {
    const { user, notice } = await addEntry('pending', open)
    expect(notice).toHaveTextContent('no longer requires')
    expect(screen.queryByRole('link', { name: 'Open approvals' })).toBeNull()
    api.post.mockResolvedValueOnce({ id: 'e1', status: 'active' })
    await user.click(screen.getByRole('button', { name: 'Put in effect' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/activate', {})
    )
  })

  it('inactive: Activate', async () => {
    const { user, notice } = await addEntry('inactive', strict)
    expect(notice).toHaveTextContent('but deactivated')
    api.post.mockResolvedValueOnce({ id: 'e1', status: 'active' })
    await user.click(screen.getByRole('button', { name: 'Activate' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/activate', {})
    )
  })

  it('expired: Renew for the one-off limit', async () => {
    const { user, notice } = await addEntry('expired', strict)
    expect(notice).toHaveTextContent('but expired')
    api.put.mockResolvedValueOnce({ id: 'e1', status: 'active' })
    await user.click(screen.getByRole('button', { name: 'Renew for 7 days' }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/scope/targets/e1', { expires_in_days: 7 })
    )
  })

  it('rejected: no action, Show it opens the rejected entry', async () => {
    const { notice } = await addEntry('rejected', strict)
    expect(notice).toHaveTextContent('Remove the rejected entry to add it again.')
    expect(
      screen.queryByRole('button', { name: /Approve|Activate|Renew|Put in effect/ })
    ).toBeNull()
    expect(screen.getByRole('link', { name: 'Show it' })).toHaveAttribute(
      'href',
      '/scope?tab=in&q=*.example.com&status=rejected'
    )
  })

  it('active: only Show it, handled on the page when it can', async () => {
    serve(strict)
    api.post.mockRejectedValueOnce(conflict('entry', 'active'))
    const show = vi.fn()
    const onOpenChange = vi.fn()
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={onOpenChange} onShowExisting={show} />)
    await user.type(await screen.findByLabelText('What'), '*.example.com')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByTestId('scope-existing')).toHaveTextContent('is already in scope.')
    await user.click(screen.getByRole('button', { name: 'Show it' }))
    expect(onOpenChange).toHaveBeenCalledWith(false)
    expect(show).toHaveBeenCalledWith(expect.stringContaining('tab=in'))
  })

  it('another error keeps the plain message', async () => {
    serve(strict)
    api.post.mockRejectedValueOnce(Object.assign(new Error('boom'), { code: 'X' }))
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('What'), 'acme.io')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByText('boom')).toBeInTheDocument()
    expect(screen.queryByTestId('scope-existing')).toBeNull()
  })
})

describe('ScopeExclusionDialog on a duplicate', () => {
  it('pending, Strict: an exclusion approver may approve it', async () => {
    serve(strict)
    api.post.mockRejectedValueOnce(conflict('exclusion', 'pending'))
    const user = userEvent.setup()
    wrap(<ScopeExclusionDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('What'), 'prod.example.com')
    await user.type(screen.getByLabelText(/Reason/), 'fragile')
    await user.click(screen.getByRole('button', { name: /exclusion|out of scope/i }))
    expect(await screen.findByTestId('scope-existing')).toHaveTextContent(
      'prod.example.com is already out of scope and is waiting for approval.'
    )
    api.post.mockResolvedValueOnce({ id: 'x1', status: 'active' })
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/exclusions/x1/approve', {})
    )
  })
})
