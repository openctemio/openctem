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
      id: 'domain:*.dev.example.com.au',
      kind: 'domain_wildcard',
      target_type: 'domain',
      pattern: '*.dev.example.com.au',
      strength: 'strong',
      covered: 12,
      covered_sample: ['a.dev.example.com.au', 'b.dev.example.com.au'],
      blocked: 1,
      blocked_sample: [{ name: 'old.dev.example.com.au', code: 'rejected' }],
      hints: [{ kind: 'verified_domain', value: 'example.com.au' }],
    },
  ],
  individual: [{ asset_id: 'x', name: '104.16.1.2', shared_ip: true }],
}

const preview = {
  action: 'accept_rule',
  allowed: true,
  entry: {
    kind: 'scope_target',
    pattern: '*.dev.example.com.au',
    status: 'pending',
    approvals_required: 1,
  },
  would_confirm: [{ asset_id: 'a', name: 'a.dev.example.com.au' }],
  would_reject: [],
  stays_blocked: [{ asset_id: 'o', name: 'old.dev.example.com.au', code: 'rejected' }],
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
    const card = (await screen.findByText('*.dev.example.com.au')).closest('li')!
    expect(
      within(card).getByText('Covers dev.example.com.au and every name below it')
    ).toBeInTheDocument()
    expect(within(card).getByText('Strong')).toBeInTheDocument()
    expect(
      within(card).getByText(/1 stay out: old\.dev\.example\.com\.au \(Marked not ours\)/)
    ).toBeInTheDocument()
    expect(
      within(card).getByText('Under example.com.au, a domain you verified')
    ).toBeInTheDocument()
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
      expect.objectContaining({ action: 'accept_rule', pattern: '*.dev.example.com.au' })
    )

    const apply = within(dialog).getByRole('button', { name: 'Accept as rule' })
    expect(apply).toBeDisabled() // no reason yet
    await user.type(within(dialog).getByLabelText('Reason'), 'OPS-12')
    await user.click(apply)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/rules', {
        action: 'accept_rule',
        target_type: 'domain',
        pattern: '*.dev.example.com.au',
        reason: 'OPS-12',
      })
    )
    expect(toast.success).toHaveBeenCalledWith(
      '*.dev.example.com.au is waiting for approval',
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
    await screen.findByText('*.dev.example.com.au')
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
                    name: 'a.example.co.uk',
                    state: 'needs_review',
                    covered_by: { kind: 'scope_target', pattern: '*.example.co.uk' },
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
    expect(await screen.findByText('*.example.co.uk')).toBeInTheDocument()
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

  it('an address row says why it waits, what resolves to it, and offers the server fixes', async () => {
    api.get.mockImplementation((url: string) =>
      Promise.resolve(
        url.includes('/candidates/suggestions')
          ? { suggestions: [] }
          : url.includes('/easm/summary')
            ? { attribution: { review_by_reason: {} } }
            : {
                total: 2,
                data: [
                  {
                    asset_id: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60',
                    name: '198.51.100.20',
                    type: 'ip_address',
                    state: 'needs_review',
                    hint: 'ip_needs_ip_entry',
                    resolved_from: ['example.co.uk', 'www.example.co.uk'],
                    network: { asn: 'AS64500', org: 'EXAMPLECO', shared: false, org_matches: true },
                    fixes: [
                      { action: 'add_entry', target_type: 'ip_address', pattern: '198.51.100.20' },
                      { action: 'add_entry', target_type: 'cidr', pattern: '198.51.100.0/24' },
                    ],
                  },
                  {
                    asset_id: '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61',
                    name: '104.16.1.2',
                    type: 'ip_address',
                    state: 'needs_review',
                    hint: 'ip_needs_ip_entry',
                    network: {
                      asn: 'AS13335',
                      org: 'CLOUDFLARENET',
                      shared: true,
                      shared_provider: 'Cloudflare',
                    },
                  },
                ],
              }
      )
    )
    wrap(<EASMReviewQueue />)
    const ip = (await screen.findByText('198.51.100.20')).closest('tr')!
    expect(within(ip).getByText(/Names never grant their addresses/)).toBeInTheDocument()
    expect(within(ip).getByText('www.example.co.uk')).toBeInTheDocument()
    expect(within(ip).getByText(/matches your organization/)).toBeInTheDocument()
    expect(
      within(ip).getByRole('button', { name: 'Add to scope: 198.51.100.20' })
    ).toBeInTheDocument()
    expect(
      within(ip).getByRole('button', { name: 'Add to scope: 198.51.100.0/24' })
    ).toBeInTheDocument()

    const cdn = screen.getByText('104.16.1.2').closest('tr')!
    expect(
      within(cdn).getByText(/shared provider space \(Cloudflare\); it cannot be added/)
    ).toBeInTheDocument()
    expect(within(cdn).queryByRole('button', { name: /Add/ })).not.toBeInTheDocument()
  })
})
