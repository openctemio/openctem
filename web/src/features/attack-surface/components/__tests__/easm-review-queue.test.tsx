/**
 * The review queue lists what the server returns for the viewer, sends one
 * bulk decision with the selected asset ids, reports assets the viewer may no
 * longer act on, and offers no decision controls without assets:write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) => p !== actual.Permission.AssetsWrite || perms.write,
    }),
  }
})
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
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
    },
  ],
}

beforeEach(() => {
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
    await user.click(within(bar).getByRole('button', { name: /Confirm/ }))
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/decisions', {
      asset_ids: [A, B],
      state: 'confirmed',
    })
    expect(toast.success).toHaveBeenCalledWith('1 asset set to confirmed')
    expect(toast.warning).toHaveBeenCalled()
  })

  it('offers no decisions without assets:write', async () => {
    perms.write = false
    api.get.mockImplementation(byUrl(queue))
    wrap(<EASMReviewQueue />)
    await screen.findByText('api.acme.io')
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(screen.getByText(/needs the assets:write permission/)).toBeInTheDocument()
  })
})
