/**
 * The review queue lists what the server returns for the viewer, sends one
 * bulk decision with the selected asset ids, reports assets the viewer may no
 * longer act on, and offers no decision controls without assets:write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true, del: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) =>
        (p !== actual.Permission.AssetsWrite || perms.write) &&
        (p !== actual.Permission.ScopeDelete || perms.del),
    }),
  }
})
const toast = vi.hoisted(() => ({
  success: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
}))
vi.mock('sonner', () => ({ toast }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))

const { EASMReviewQueue } = await import('../easm-review-queue')

/** The queue for the candidates list; empty answers for the summary and suggestions. */
const byUrl = (page: unknown) => (url: string) =>
  Promise.resolve(
    url.includes('/candidates/suggestions')
      ? { suggestions: [], individual: [] }
      : url.includes('/easm/summary')
        ? {}
        : page
  )

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const A = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
const B = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c'
const queue = {
  total: 2,
  data: [
    {
      asset_id: A,
      name: 'api.acme.io',
      type: 'subdomain',
      state: 'needs_review',
      confidence: 85,
      in_queue_since: '2026-10-01T00:00:00Z',
      evidence: [
        {
          rule: 'fqdn_under_asserted_root',
          technique: 'cert_transparency',
          source: 'crt.sh',
          weight: 0.85,
          observed: { root: 'acme.io' },
          first_observed_at: '2026-10-01T00:00:00Z',
          last_observed_at: '2026-10-01T00:00:00Z',
        },
      ],
    },
    {
      asset_id: B,
      name: 'old.acme.io',
      type: 'subdomain',
      state: 'candidate',
      confidence: 30,
      evidence: [],
      children: { service: 3, certificate: 1 },
    },
  ],
}

beforeEach(() => {
  perms.del = true
  window.history.replaceState(null, '', '/attack-surface/review')
  api.get.mockReset()
  api.post.mockReset()
  toast.success.mockReset()
  toast.warning.mockReset()
  perms.write = true
})

describe('EASMReviewQueue', () => {
  it('lists the queue with its evidence, most confident first as served', async () => {
    api.get.mockImplementation(byUrl(queue))
    wrap(<EASMReviewQueue />)
    expect(await screen.findByText('api.acme.io')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith(
      '/api/v1/easm/candidates?states=needs_review%2Ccandidate&page=1&per_page=50'
    )
    expect(
      screen.getByText(/Under acme\.io, a domain you listed but have not verified/)
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'api.acme.io' })).toHaveAttribute(
      'href',
      `/assets/${A}`
    )
  })

  it('confirms the selected assets in one decision and reports the rest', async () => {
    api.get.mockImplementation(byUrl(queue))
    api.post.mockResolvedValue({
      decided: [{ asset_id: A, from: 'needs_review', to: 'confirmed' }],
      not_found: [B],
    })
    const user = userEvent.setup()
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    await user.click(screen.getByRole('checkbox', { name: 'Select all' }))
    const bar = screen.getByRole('toolbar', { name: 'Decide selected assets' })
    await user.click(within(bar).getByRole('button', { name: /Ours: add to scope/ }))
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/decisions', {
      asset_ids: [A, B],
      state: 'confirmed',
    })
    expect(toast.success).toHaveBeenCalledWith('1 asset set to Confirmed')
    expect(toast.warning).toHaveBeenCalled()
  })

  it('lists a host with the children that follow it, never the children as rows', async () => {
    api.get.mockImplementation(byUrl(queue))
    wrap(<EASMReviewQueue />)
    expect(await screen.findByText('+ 1 certificate, 3 services')).toBeInTheDocument()
  })

  it('says which scope entries a confirmation added, and Undo removes exactly those', async () => {
    api.get.mockImplementation(byUrl(queue))
    api.del.mockResolvedValue(undefined)
    api.post.mockResolvedValue({
      decided: [{ asset_id: A, from: 'needs_review', to: 'confirmed' }],
      not_found: [],
      scope: {
        entries: [
          {
            asset_id: A,
            name: 'api.acme.io',
            pattern: 'api.acme.io',
            outcome: 'added',
            target_id: 'T1',
            status: 'active',
          },
          {
            asset_id: B,
            name: 'old.acme.io',
            pattern: 'old.acme.io',
            outcome: 'covered',
            target_id: 'T0',
          },
        ],
      },
    })
    const user = userEvent.setup()
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    await user.click(screen.getByRole('checkbox', { name: 'Select all' }))
    const bar = screen.getByRole('toolbar', { name: 'Decide selected assets' })
    await user.click(within(bar).getByRole('button', { name: /Ours: add to scope/ }))
    const call = toast.success.mock.calls.find((c) => c[0] === 'Added api.acme.io to scope')
    expect(call).toBeDefined()
    call![1].action.onClick()
    await waitFor(() => expect(api.del).toHaveBeenCalledTimes(1))
    expect(api.del).toHaveBeenCalledWith('/api/v1/scope/targets/T1')
  })

  it('tells a caller without scope write that only ownership was recorded', async () => {
    api.get.mockImplementation(byUrl(queue))
    api.post.mockResolvedValue({
      decided: [{ asset_id: A, from: 'needs_review', to: 'confirmed' }],
      not_found: [],
      scope: { skipped: 'needs_scope_write', entries: [] },
    })
    const user = userEvent.setup()
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    await user.click(screen.getByRole('checkbox', { name: 'Select all' }))
    const bar = screen.getByRole('toolbar', { name: 'Decide selected assets' })
    await user.click(within(bar).getByRole('button', { name: /Ours: add to scope/ }))
    expect(toast.info).toHaveBeenCalledWith(
      'Recorded as yours. Adding them to scope needs permission to edit scope.'
    )
  })

  it('offers no decisions without assets:write', async () => {
    perms.write = false
    api.get.mockImplementation(byUrl(queue))
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(screen.getByText(/needs permission to edit assets/)).toBeInTheDocument()
  })

  it('offers no Undo on added scope entries without scope delete', async () => {
    perms.del = false
    api.get.mockImplementation(byUrl(queue))
    api.post.mockResolvedValue({
      decided: [{ asset_id: A, from: 'needs_review', to: 'confirmed' }],
      not_found: [],
      scope: {
        entries: [
          {
            asset_id: A,
            name: 'api.acme.io',
            pattern: 'api.acme.io',
            outcome: 'added',
            target_id: 'T1',
          },
        ],
      },
    })
    const user = userEvent.setup()
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    await user.click(screen.getByRole('checkbox', { name: 'Select all' }))
    const bar = screen.getByRole('toolbar', { name: 'Decide selected assets' })
    await user.click(within(bar).getByRole('button', { name: /Ours: add to scope/ }))
    const call = toast.success.mock.calls.find((c) => c[0] === 'Added api.acme.io to scope')
    expect(call).toBeDefined()
    expect(call![1].action).toBeUndefined()
  })

  it('shows skeleton rows, not a text, while loading', async () => {
    api.get.mockImplementation(() => new Promise(() => {}))
    const { container } = wrap(<EASMReviewQueue />)
    await waitFor(() =>
      expect(container.querySelectorAll('[data-slot="skeleton"]').length).toBeGreaterThan(0)
    )
    expect(screen.queryByText('Loading…')).toBeNull()
  })

  it('keeps the search in the URL like the tab and the reason', async () => {
    api.get.mockImplementation(byUrl(queue))
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    await userEvent.type(screen.getByRole('searchbox', { name: /^Search names/ }), 'api')
    expect(new URLSearchParams(window.location.search).get('q')).toBe('api')
  })
})
