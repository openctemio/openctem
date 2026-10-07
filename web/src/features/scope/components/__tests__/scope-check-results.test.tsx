/**
 * A refused target reads the same wherever it comes from (the dry run or a
 * TARGET_OUT_OF_SCOPE error), with the fixes the server offered.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, useHasPermission: () => true, usePermissions: () => ({ can: () => true }) }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopeCheckList, refusedFromError, fixHref, viaText } =
  await import('../scope-check-results')

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const ASSET = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'

beforeEach(() => {
  api.get
    .mockReset()
    .mockResolvedValue({ one_off_targets: 'admins_and_requests', one_off_max_days: 7 })
  api.post.mockReset()
  toast.success.mockReset()
})

describe('ScopeCheckList', () => {
  it('lists refused targets first with reason and fixes; allowed ones say through what', () => {
    wrap(
      <ScopeCheckList
        showAllowed
        results={[
          {
            target: 'app.acme.io',
            allowed: true,
            via: { kind: 'scope_target', pattern: '*.acme.io', proof: 'asserted' },
          },
          {
            target: 'promo.net',
            allowed: false,
            code: 'no_entry',
            message: 'server text',
            fixes: [
              { action: 'allow_temporarily', pattern: 'promo.net', target_type: 'domain', days: 7 },
              { action: 'add_entry', pattern: '*.promo.net', target_type: 'domain' },
            ],
          },
        ]}
      />
    )
    const rows = screen.getAllByRole('listitem')
    expect(rows[0]).toHaveTextContent('promo.net')
    expect(rows[0]).toHaveTextContent('Not in scope')
    expect(rows[0]).toHaveTextContent('No scope entry, seed or verified domain covers this target.')
    expect(screen.getByRole('button', { name: 'Allow for 7 days' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add to scope' })).toBeInTheDocument()
    expect(rows[1]).toHaveTextContent('Allowed by *.acme.io')
  })

  it('an approve fix approves the entry in place', async () => {
    api.post.mockResolvedValue({ status: 'active' })
    const onApplied = vi.fn()
    const user = userEvent.setup()
    wrap(
      <ScopeCheckList
        onApplied={onApplied}
        results={[
          {
            target: 'x.acme.io',
            allowed: false,
            code: 'entry_pending',
            rule: { kind: 'scope_target', id: 'e1', pattern: '*.acme.io' },
            fixes: [{ action: 'approve_entry', id: 'e1' }],
          },
        ]}
      />
    )
    expect(screen.getByText(/waiting for approval\. \(\*\.acme\.io\)/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Approve the entry' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/approve', {})
    )
    expect(onApplied).toHaveBeenCalled()
  })

  it('"Allow for 7 days" opens the entry dialog prefilled as a one-off', async () => {
    const user = userEvent.setup()
    wrap(
      <ScopeCheckList
        results={[
          {
            target: 'https://promo.net/landing',
            allowed: false,
            code: 'no_entry',
            fixes: [
              { action: 'allow_temporarily', pattern: 'promo.net', target_type: 'domain', days: 7 },
            ],
          },
        ]}
      />
    )
    await user.click(screen.getByRole('button', { name: 'Allow for 7 days' }))
    expect(await screen.findByDisplayValue('promo.net')).toBeInTheDocument()
    expect(screen.getByLabelText('Days')).toHaveValue(7)
  })

  it('shows hint-only fixes as text and link fixes as links', () => {
    wrap(
      <ScopeCheckList
        results={[
          {
            target: 'x.acme.io',
            allowed: false,
            code: 'proof_required',
            fixes: [{ action: 'use_tenant_sensor' }],
          },
          {
            target: 'old.acme.io',
            allowed: false,
            code: 'rejected',
            rule: { kind: 'asset', id: ASSET },
            fixes: [{ action: 'review_asset', id: ASSET }],
          },
        ]}
      />
    )
    expect(screen.getByText('Use your own sensor')).not.toHaveAttribute('href')
    expect(screen.getByRole('link', { name: 'Review ownership' })).toHaveAttribute(
      'href',
      `/assets/${ASSET}`
    )
  })
})

describe('refusals from errors', () => {
  it('reads details.refused[] of TARGET_OUT_OF_SCOPE and ignores anything else', () => {
    const err = {
      code: 'TARGET_OUT_OF_SCOPE',
      details: {
        refused: [
          { target: 'a.net', code: 'no_entry', message: 'm', fixes: [] },
          { nope: true },
          'junk',
        ],
      },
    }
    expect(refusedFromError(err)).toEqual([
      { target: 'a.net', code: 'no_entry', message: 'm', fixes: [] },
    ])
    expect(refusedFromError(new Error('x'))).toEqual([])
    expect(refusedFromError({ details: { refused: 'x' } })).toEqual([])
  })

  it('never links a rule id that is not an asset id', () => {
    expect(fixHref({ action: 'review_asset' }, { kind: 'asset', id: 'javascript:alert(1)' })).toBe(
      '/attack-surface/review'
    )
    expect(fixHref({ action: 'add_zone' })).toBe('/sensors?tab=zones')
    expect(fixHref({ action: 'approve_entry' })).toBeNull()
  })

  it('says where an allowed target authority comes from', () => {
    expect(viaText({ kind: 'verified_domain', pattern: 'acme.io' })).toBe(
      'Allowed under the verified domain acme.io'
    )
    expect(viaText({ kind: 'internal' })).toBe('Private target: routed by its scan zone')
  })
})
