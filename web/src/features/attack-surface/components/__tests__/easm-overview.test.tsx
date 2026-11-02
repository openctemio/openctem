/**
 * The overview's middle row (research/353 D4): what to fix first, each row
 * opening its asset, and whether discovery keeps up, with the decisions as
 * the next step and the monitoring settings in a drawer.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { EASMOverview, exposureTypeLabel } from '../easm-overview'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('../easm-monitoring-card', () => ({
  EASMMonitoringCard: () => <div data-testid="monitoring-card" />,
}))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => true }), useCanMutate: () => true }
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
      asset_id: '0198f0e2-3333-7000-8000-000000000003',
      asset_name: 'old.acme.com',
      last_seen: '2026-10-02T00:00:00Z',
    },
  ],
  monitoring: { ct_domains_watched: 4, ct_failing: 1, ct_never_succeeded: 0 },
}

beforeEach(() => api.get.mockReset())

describe('EASMOverview', () => {
  it('lists what to fix first, each opening the asset it is on', async () => {
    api.get.mockResolvedValue(summary)
    wrap(<EASMOverview />)
    expect(await screen.findByText('Dangling CNAME: old.acme.com')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/easm/summary')
    // One request feeds both cards.
    expect(api.get).toHaveBeenCalledTimes(1)
    expect(screen.getByText('Dangling CNAME')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'old.acme.com' })).toHaveAttribute(
      'href',
      '/assets/0198f0e2-3333-7000-8000-000000000003'
    )
    expect(screen.getByRole('link', { name: 'All 7 open' })).toHaveAttribute('href', '/exposures')
  })

  it('shows whether discovery keeps up, with the decisions as the next step', async () => {
    api.get.mockResolvedValue(summary)
    wrap(<EASMOverview />)
    const health = await screen.findByTestId('easm-discovery-health')
    await within(health).findByText('Found, not yet decided')
    expect(within(health).getByText('12')).toBeInTheDocument()
    expect(within(health).getByText('1 failing')).toBeInTheDocument()
    expect(within(health).getByRole('link', { name: 'Decide 12' })).toHaveAttribute(
      'href',
      '/attack-surface/review'
    )
  })

  it('opens the monitoring settings in a drawer, not inline', async () => {
    api.get.mockResolvedValue(summary)
    wrap(<EASMOverview />)
    const health = await screen.findByTestId('easm-discovery-health')
    await within(health).findByText('Found, not yet decided')
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.click(within(health).getByRole('button', { name: 'Monitoring settings' }))
    expect(await screen.findByRole('dialog', { name: 'Monitoring settings' })).toBeInTheDocument()
  })

  it('shows the empty state when nothing is open, and no decide button with nothing waiting', async () => {
    api.get.mockResolvedValue({
      ...summary,
      top_risks: [],
      exposures: { open: 0 },
      attribution: { ...summary.attribution, needs_review: 0 },
    })
    wrap(<EASMOverview />)
    expect(await screen.findByText('No open external risks')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'All exposures' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /^Decide/ })).toBeNull()
  })

  it('labels exposure types in words', () => {
    expect(exposureTypeLabel('email_security_weak')).toBe('Weak email security')
    expect(exposureTypeLabel('bucket_public')).toBe('Bucket Public')
    expect(exposureTypeLabel('not_a_type')).toBe('not a type')
  })
})
