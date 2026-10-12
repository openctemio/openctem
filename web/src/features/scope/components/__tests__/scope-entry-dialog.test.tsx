/**
 * Adding to scope (RFC-054 §6.1): an approver adds an entry (the domain and
 * every name below it by default); a member only requests one name for a few
 * days, with a reason. The server's codes come back as sentences.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ approve: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) => p !== actual.Permission.ScopeApprove || perms.approve,
    usePermissions: () => ({ can: () => true, isOwner: () => false }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopeEntryDialog, isSingleTarget, approvalsForNew } = await import('../scope-entry-dialog')

const settings = {
  auto_join_discovered: true,
  one_off_targets: 'admins_and_requests',
  one_off_max_days: 7,
  widening_approvals: null,
  default_max_tier: 't1',
  effective_widening_approvals: 1,
  admin_count: 2,
  active_proof: 'off',
}

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.get.mockReset().mockResolvedValue(settings)
  api.post.mockReset()
  toast.success.mockReset()
  perms.approve = true
})

describe('ScopeEntryDialog', () => {
  it('an approver adds the domain and every name below it by default', async () => {
    api.post.mockResolvedValue({ pattern: '*.acme.io', status: 'pending', approvals_required: 1 })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('What'), 'acme.io')
    expect(screen.getByText('acme.io and every name below it · permanent')).toBeInTheDocument()
    expect(screen.getByText(/Needs 1 approval from another approver/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets', {
        target_type: 'domain',
        pattern: '*.acme.io',
        description: undefined,
        reason: undefined,
        max_tier: 't1',
      })
    )
    expect(toast.success).toHaveBeenCalledWith(
      '*.acme.io is waiting for approval',
      expect.anything()
    )
  })

  it('typing *.x picks "x and every name below it"; "only" stores the exact name', async () => {
    api.post.mockResolvedValue({ pattern: 'acme.io', status: 'active' })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    const input = await screen.findByLabelText('What')
    await user.type(input, '*.acme.io')
    expect(input).toHaveValue('acme.io')
    await user.click(screen.getByText('acme.io only'))
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: 'acme.io' })
      )
    )
  })

  it('a one-off from a fix needs a reason and sends its days', async () => {
    api.post.mockResolvedValue({ pattern: 'promo.net', status: 'active' })
    const user = userEvent.setup()
    wrap(
      <ScopeEntryDialog
        open
        onOpenChange={() => {}}
        draft={{ target_type: 'domain', pattern: 'promo.net', duration: 'one_off', days: 5 }}
      />
    )
    await screen.findByDisplayValue('promo.net')
    await user.click(screen.getByText('promo.net only'))
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Say why this target may be probed/)
    expect(api.post).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('Reason'), 'MKT-9')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: 'promo.net', expires_in_days: 5, reason: 'MKT-9' })
      )
    )
  })

  it('a member requests one name for a few days, never a wildcard', async () => {
    perms.approve = false
    api.post.mockResolvedValue({ pattern: 'shop.acme.io', status: 'pending' })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(await screen.findByRole('heading', { name: 'Request access' })).toBeInTheDocument()
    // No coverage or duration choice: a request is one name, one-off.
    expect(screen.queryByText('Covers')).not.toBeInTheDocument()
    expect(screen.queryByText('Permanent')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('What'), '*.acme.io')
    await user.type(screen.getByLabelText('Reason'), 'need it')
    await user.click(screen.getByRole('button', { name: 'Send request' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/one name or address/)
    expect(api.post).not.toHaveBeenCalled()

    await user.clear(screen.getByLabelText('What'))
    await user.type(screen.getByLabelText('What'), 'shop.acme.io')
    await user.click(screen.getByRole('button', { name: 'Send request' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: 'shop.acme.io', expires_in_days: 7, reason: 'need it' })
      )
    )
    expect(toast.success).toHaveBeenCalledWith('Request sent', expect.anything())
  })

  it('a member sees why they cannot request when the organization does not accept requests', async () => {
    perms.approve = false
    api.get.mockResolvedValue({ ...settings, one_off_targets: 'admins' })
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(
      await screen.findByText('Your organization does not accept scope requests from members.')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Send request' })).not.toBeInTheDocument()
  })

  it('shows the server refusal as a sentence', async () => {
    api.post.mockRejectedValue(Object.assign(new Error('raw'), { code: 'PUBLIC_SUFFIX' }))
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('What'), 'com.vn')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/public suffix/i)
  })
})

describe('ScopeEntryDialog: letter of authorization', () => {
  // Radix Select uses pointer capture and scrollIntoView, which jsdom lacks.
  beforeEach(() => {
    Element.prototype.hasPointerCapture ??= () => false
    Element.prototype.releasePointerCapture ??= () => {}
    Element.prototype.scrollIntoView ??= () => {}
  })

  it('names an in-effect letter; revoked and expired letters are not offered', async () => {
    api.get.mockImplementation(async (url: string) =>
      url.startsWith('/api/v1/scope/letters')
        ? {
            data: [
              {
                id: 'l1',
                title: 'Client LoA',
                in_effect: true,
                valid_until: '2027-01-01T00:00:00Z',
              },
              { id: 'l2', title: 'Old LoA', in_effect: false, valid_until: '2025-01-01T00:00:00Z' },
              {
                id: 'l3',
                title: 'Revoked LoA',
                in_effect: false,
                revoked_at: '2026-10-01T00:00:00Z',
                valid_until: '2027-01-01T00:00:00Z',
              },
            ],
          }
        : settings
    )
    api.post.mockResolvedValue({ pattern: '*.client.io', status: 'pending', approvals_required: 1 })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('What'), 'client.io')
    await user.click(await screen.findByLabelText('Authorized by'))
    expect(screen.queryByRole('option', { name: /Old LoA/ })).toBeNull()
    expect(screen.queryByRole('option', { name: /Revoked LoA/ })).toBeNull()
    await user.click(screen.getByRole('option', { name: /Client LoA/ }))
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({
          pattern: '*.client.io',
          authorization_source: 'authorization_letter',
          letter_id: 'l1',
        })
      )
    )
  })

  it('offers no choice without a usable letter', async () => {
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await screen.findByLabelText('What')
    expect(screen.queryByLabelText('Authorized by')).toBeNull()
  })
})

describe('request and approval rules', () => {
  it('single names only for requests', () => {
    expect(isSingleTarget('domain', 'shop.acme.io')).toBe(true)
    expect(isSingleTarget('domain', '*.acme.io')).toBe(false)
    expect(isSingleTarget('ip_address', '203.0.113.7')).toBe(true)
    expect(isSingleTarget('ip_range', '203.0.113.0/24')).toBe(false)
  })

  it('a request needs at least one approval; t2 always one', () => {
    expect(approvalsForNew({ canApprove: false, effective: 0, tier: 't1' })).toBe(1)
    expect(approvalsForNew({ canApprove: true, effective: 0, tier: 't1' })).toBe(0)
    expect(approvalsForNew({ canApprove: true, effective: 0, tier: 't2' })).toBe(1)
    expect(approvalsForNew({ canApprove: true, effective: 2, tier: 't1' })).toBe(2)
  })
})

describe('ScopeEntryDialog: duration follows the policy', () => {
  it('a T2 entry defaults to the longest allowed expiry; Permanent is disabled with who can change it', async () => {
    api.get.mockResolvedValue({ ...settings, t2_max_days: 30, t2_permanent_allowed: false })
    api.post.mockResolvedValue({ pattern: '*.vndirect.com.vn', status: 'pending' })
    const user = userEvent.setup()
    wrap(
      <ScopeEntryDialog
        open
        onOpenChange={() => {}}
        draft={{ target_type: 'domain', pattern: '*.vndirect.com.vn', tier: 't2' }}
      />
    )
    const thirty = await screen.findByRole('radio', { name: '30 days' })
    // No error before the user acts.
    expect(screen.queryByRole('alert')).toBeNull()
    expect(thirty).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('radio', { name: 'Permanent' })).toBeDisabled()
    expect(screen.queryByRole('radio', { name: '90 days' })).toBeNull()
    expect(screen.getByRole('link', { name: 'Ask an owner' })).toHaveAttribute(
      'href',
      '/settings/scope'
    )
    expect(screen.getByTestId('expiry')).toHaveTextContent(/^Expires \d{1,2} \w{3} \d{4}$/)
    await user.type(screen.getByLabelText('Reason'), 'pentest OPS-1')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({
          pattern: '*.vndirect.com.vn',
          max_tier: 't2',
          expires_in_days: 30,
        })
      )
    )
  })

  it('a T2 entry defaults to Permanent when an owner allows it', async () => {
    api.get.mockResolvedValue({ ...settings, t2_max_days: 365, t2_permanent_allowed: true })
    wrap(
      <ScopeEntryDialog
        open
        onOpenChange={() => {}}
        draft={{ target_type: 'domain', pattern: 'acme.io', tier: 't2' }}
      />
    )
    const permanent = await screen.findByRole('radio', { name: 'Permanent' })
    await waitFor(() => expect(permanent).toHaveAttribute('aria-checked', 'true'))
    expect(screen.getByRole('radio', { name: '1 year' })).toBeEnabled()
    expect(screen.queryByRole('link', { name: 'Ask an owner' })).toBeNull()
  })

  it('a custom date is bounded from tomorrow to the policy limit', async () => {
    api.get.mockResolvedValue({ ...settings, t2_max_days: 90, t2_permanent_allowed: false })
    const user = userEvent.setup()
    wrap(
      <ScopeEntryDialog
        open
        onOpenChange={() => {}}
        draft={{ target_type: 'domain', pattern: 'acme.io', tier: 't2' }}
      />
    )
    await user.click(await screen.findByRole('radio', { name: 'Custom date' }))
    const date = screen.getByLabelText('Expires on')
    const day = (n: number) => {
      const d = new Date()
      d.setHours(0, 0, 0, 0)
      d.setDate(d.getDate() + n)
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
    }
    expect(date).toHaveAttribute('min', day(1))
    expect(date).toHaveAttribute('max', day(90))
  })

  it('a member request offers no Permanent at all', async () => {
    perms.approve = false
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await screen.findByRole('radio', { name: '7 days' })
    expect(screen.queryByRole('radio', { name: 'Permanent' })).toBeNull()
  })
})

describe('ScopeEntryDialog: tier ceilings follow the scan approval mode', () => {
  it('outside Strict the entry has no tier to pick', async () => {
    api.get.mockReset().mockResolvedValue({
      ...settings,
      approval_policy: {
        scan_approval: 'on',
        source: 'organization',
        entries_need_approval: false,
        tier_ceilings: false,
      },
    })
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(await screen.findByText(/An entry covers every probe/)).toBeInTheDocument()
    expect(screen.getByText('Deepest probe allowed').closest('div')).toHaveClass('hidden')
  })

  it('in Strict the tier is a ceiling to pick', async () => {
    api.get.mockReset().mockResolvedValue({
      ...settings,
      approval_policy: {
        scan_approval: 'strict',
        source: 'organization',
        entries_need_approval: true,
        tier_ceilings: true,
      },
    })
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(await screen.findByText('Deepest probe allowed')).toBeVisible()
    expect(screen.queryByText(/An entry covers every probe/)).not.toBeInTheDocument()
  })
})

describe('ScopeEntryDialog: a member outside Strict adds directly', () => {
  it('no request: a wildcard, no reason, in scope at once', async () => {
    perms.approve = false
    api.get.mockReset().mockResolvedValue({
      ...settings,
      effective_widening_approvals: 0,
      approval_policy: {
        scan_approval: 'off',
        source: 'organization',
        entries_need_approval: false,
        tier_ceilings: false,
      },
    })
    api.post.mockResolvedValue({ pattern: '*.acme.io', status: 'active' })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(await screen.findByRole('heading', { name: 'Add to scope' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Send request' })).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('What'), 'acme.io')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: '*.acme.io' })
      )
    )
    expect(toast.success).toHaveBeenCalledWith('*.acme.io is in scope')
  })
})
