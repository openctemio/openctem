/**
 * Review by rule (RFC-054 §6.7): suggestion cards with evidence; Accept as
 * rule shows the preview (what is confirmed, what stays out, approvals,
 * step-up) before anything changes, and needs a reason; the review queue
 * filters by reason and says what covers each name.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ approve: true, scopeWrite: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  const can = (p: string) =>
    (p !== actual.Permission.ScopeApprove || perms.approve) &&
    (p !== actual.Permission.ScopeWrite || perms.scopeWrite)
  return { ...actual, useHasPermission: can, usePermissions: () => ({ can }) }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

const { EASMRuleSuggestions } = await import('../easm-rule-suggestions')
const { EASMReviewQueue } = await import('../easm-review-queue')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const suggestions = {
  suggestions: [
    {
      id: 'domain:*.dev.ipas.com.vn',
      kind: 'domain_wildcard',
      target_type: 'domain',
      pattern: '*.dev.ipas.com.vn',
      strength: 'strong',
      covered: 12,
      covered_sample: ['a.dev.ipas.com.vn', 'b.dev.ipas.com.vn'],
      blocked: 1,
      blocked_sample: [{ name: 'old.dev.ipas.com.vn', code: 'rejected' }],
      hints: [{ kind: 'verified_domain', value: 'ipas.com.vn' }],
    },
  ],
  individual: [{ asset_id: 'x', name: '104.16.1.2', shared_ip: true }],
}

const preview = {
  action: 'accept_rule',
  allowed: true,
  entry: {
    kind: 'scope_target',
    pattern: '*.dev.ipas.com.vn',
    status: 'pending',
    approvals_required: 1,
  },
  would_confirm: [{ asset_id: 'a', name: 'a.dev.ipas.com.vn' }],
  would_reject: [],
  stays_blocked: [{ asset_id: 'o', name: 'old.dev.ipas.com.vn', code: 'rejected' }],
  step_up_required: true,
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  toast.success.mockReset()
  perms.approve = true
  perms.scopeWrite = true
})

describe('suggested rules', () => {
  it('show what each rule covers, what stays out, and the evidence', async () => {
    api.get.mockResolvedValue(suggestions)
    wrap(<EASMRuleSuggestions onApplied={() => {}} />)
    const card = (await screen.findByText('*.dev.ipas.com.vn')).closest('li')!
    expect(
      within(card).getByText('Covers dev.ipas.com.vn and every name below it')
    ).toBeInTheDocument()
    expect(within(card).getByText('Strong')).toBeInTheDocument()
    expect(
      within(card).getByText(/1 stay out: old\.dev\.ipas\.com\.vn \(Marked not ours\)/)
    ).toBeInTheDocument()
    expect(within(card).getByText('Under ipas.com.vn, a domain you verified')).toBeInTheDocument()
    expect(screen.getByText(/shared or CDN address is never grouped/)).toBeInTheDocument()
  })

  it('Accept as rule previews first, needs a reason, then applies through the widening path', async () => {
    api.get.mockResolvedValue(suggestions)
    api.post.mockImplementation((url: string) =>
      Promise.resolve(
        url.endsWith('/rules/preview')
          ? preview
          : { ...preview, entry: { ...preview.entry, id: 'e1' }, confirmed: [] }
      )
    )
    const onApplied = vi.fn()
    const user = userEvent.setup()
    wrap(<EASMRuleSuggestions onApplied={onApplied} />)
    await user.click(await screen.findByRole('button', { name: 'Accept as rule' }))

    const dialog = await screen.findByRole('dialog')
    const review = await within(dialog).findByRole('region', { name: 'Review changes' })
    expect(within(review).getByText('Confirmed as yours: 1')).toBeInTheDocument()
    expect(within(review).getByText('Stay out: 1')).toBeInTheDocument()
    expect(within(review).getByText(/Needs 1 approval from another approver/)).toBeInTheDocument()
    expect(within(review).getByText(/asked to confirm it is you/)).toBeInTheDocument()
    expect(api.post).toHaveBeenCalledWith(
      '/api/v1/easm/candidates/rules/preview',
      expect.objectContaining({ action: 'accept_rule', pattern: '*.dev.ipas.com.vn' })
    )

    const apply = within(dialog).getByRole('button', { name: 'Accept as rule' })
    expect(apply).toBeDisabled() // no reason yet
    await user.type(within(dialog).getByLabelText('Reason'), 'OPS-12')
    await user.click(apply)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/rules', {
        action: 'accept_rule',
        target_type: 'domain',
        pattern: '*.dev.ipas.com.vn',
        reason: 'OPS-12',
      })
    )
    expect(toast.success).toHaveBeenCalledWith(
      '*.dev.ipas.com.vn is waiting for approval',
      expect.anything()
    )
    expect(onApplied).toHaveBeenCalled()
  })

  it('a refused rule says why and cannot be applied', async () => {
    api.get.mockResolvedValue(suggestions)
    api.post.mockResolvedValue({
      ...preview,
      allowed: false,
      refusal: { code: 'PUBLIC_SUFFIX', message: 'raw' },
    })
    const user = userEvent.setup()
    wrap(<EASMRuleSuggestions onApplied={() => {}} />)
    await user.click(await screen.findByRole('button', { name: 'Accept as rule' }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText(/A public suffix/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('Reason'), 'x')
    expect(within(dialog).getByRole('button', { name: 'Accept as rule' })).toBeDisabled()
  })

  it('offers no rule actions without scope:write', async () => {
    perms.scopeWrite = false
    api.get.mockResolvedValue(suggestions)
    wrap(<EASMRuleSuggestions onApplied={() => {}} />)
    await screen.findByText('*.dev.ipas.com.vn')
    expect(screen.queryByRole('button', { name: 'Accept as rule' })).not.toBeInTheDocument()
  })
})

describe('review queue', () => {
  it('filters by reason and says what covers each name', async () => {
    api.get.mockImplementation((url: string) =>
      Promise.resolve(
        url.includes('/candidates/suggestions')
          ? { suggestions: [] }
          : url.includes('/easm/summary')
            ? { attribution: { review_by_reason: { fqdn_under_asserted_root: 10 } } }
            : {
                total: 2,
                data: [
                  {
                    asset_id: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b',
                    name: 'a.vndirect.com.vn',
                    state: 'needs_review',
                    covered_by: { kind: 'scope_target', pattern: '*.vndirect.com.vn' },
                  },
                  {
                    asset_id: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c',
                    name: 'promo.net',
                    state: 'needs_review',
                  },
                ],
              }
      )
    )
    const user = userEvent.setup()
    wrap(<EASMReviewQueue />)
    expect(await screen.findByText('*.vndirect.com.vn')).toBeInTheDocument()
    const promo = screen.getByText('promo.net').closest('tr')!
    expect(within(promo).getByText(/Not in scope/)).toBeInTheDocument()
    expect(within(promo).getByRole('button', { name: 'Add to scope' })).toBeInTheDocument()

    await user.click(screen.getByLabelText('Filter by reason'))
    await user.click(
      await screen.findByRole('option', { name: /Under a domain you listed, not verified \(10\)/ })
    )
    await waitFor(() =>
      expect(
        api.get.mock.calls.some(
          (c) =>
            (c[0] as string).includes('/easm/candidates?') &&
            (c[0] as string).includes('reason=fqdn_under_asserted_root')
        )
      ).toBe(true)
    )
  })
})
