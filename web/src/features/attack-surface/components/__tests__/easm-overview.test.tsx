/**
 * The EASM overview shows the server's numbers as they are: no cycle reads
 * "no cycle started" rather than 0, top risks list with their asset, and an
 * empty list gets the shared empty state.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { EASMOverview, exposureTypeLabel } from '../easm-overview'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => true }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const summary = {
  surface: { total: 42, by_type: { subdomain: 40, domain: 2 }, exposed_services: 3 },
  attribution: {
    confirmed: 30,
    legacy: 20,
    needs_review: 12,
    candidate: 0,
    dependency: 0,
    monitor_only: 0,
    rejected: 0,
  },
  new: { last_7_days: 5, last_30_days: 9 },
  exposures: { open: 7, by_severity: { high: 1, info: 6 }, by_type: [] },
  top_risks: [
    {
      id: 'e1',
      type: 'dangling_cname',
      severity: 'high',
      title: 'Dangling CNAME: old.acme.com',
      asset_name: 'old.acme.com',
      last_seen: '2026-10-02T00:00:00Z',
    },
  ],
  monitoring: { ct_domains_watched: 4, ct_failing: 1, ct_never_succeeded: 0 },
}

beforeEach(() => api.get.mockReset())

describe('EASMOverview', () => {
  it('renders the server numbers and the top risks', async () => {
    api.get.mockResolvedValue(summary)
    wrap(<EASMOverview />)
    expect(await screen.findByText('Dangling CNAME: old.acme.com')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/easm/summary')
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('no cycle started')).toBeInTheDocument()
    expect(screen.getByText('CT lookups failing')).toBeInTheDocument()
    expect(screen.getByText(/7 open in total/)).toBeInTheDocument()
    expect(screen.getByText(/Dangling CNAME · old.acme.com/)).toBeInTheDocument()
    // Names waiting for review link to the review queue.
    expect(screen.getByRole('link', { name: 'Review' })).toHaveAttribute(
      'href',
      '/attack-surface/review'
    )
  })

  it('shows the empty state when nothing is open', async () => {
    api.get.mockResolvedValue({
      ...summary,
      top_risks: [],
      exposures: { open: 0 },
      new: { ...summary.new, since_cycle: 3, cycle_start: '2026-09-01T00:00:00Z' },
    })
    wrap(<EASMOverview />)
    expect(await screen.findByText('No open external risks')).toBeInTheDocument()
    expect(screen.queryByText('no cycle started')).not.toBeInTheDocument()
  })

  it('labels exposure types in words', () => {
    expect(exposureTypeLabel('email_security_weak')).toBe('Weak email security')
    expect(exposureTypeLabel('bucket_public')).toBe('bucket public')
  })
})
