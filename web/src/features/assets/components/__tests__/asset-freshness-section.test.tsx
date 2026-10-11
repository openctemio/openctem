/**
 * Data freshness (RFC-075): each attribute class with its state, source and
 * window; never-observed passive classes; the enrichment line with its run;
 * nothing fetched without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetFreshnessSection } from '../asset-freshness-section'
import type { AssetFreshness } from '../../lib/asset-freshness'

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = []
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const fresh: AssetFreshness = {
  state: 'stale',
  classes: [
    {
      class: 'dns',
      state: 'live',
      observed_at: new Date().toISOString(),
      source: 'dnsx',
      ttl_seconds: 86400,
      passive: true,
    },
    { class: 'registration', state: 'never', ttl_seconds: 604800, passive: true },
    {
      class: 'http',
      state: 'stale',
      observed_at: '2026-01-01T00:00:00Z',
      source: 'httpx',
      ttl_seconds: 129600,
      passive: false,
    },
  ],
  enrichment: {
    reason: 'new_asset',
    requested_at: '2026-10-11T00:00:00Z',
    dispatched_at: '2026-10-11T00:01:00Z',
    outcome: 'dispatched',
    last_run_id: 'run-1',
  },
}

describe('AssetFreshnessSection', () => {
  beforeEach(() => {
    api.get.mockReset()
    perms = ['assets:read']
  })

  it('shows every class with its state, source and window, and the enrichment run', async () => {
    api.get.mockResolvedValue(fresh)
    wrap(<AssetFreshnessSection assetId="a1" />)
    expect(await screen.findByText('DNS records')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/freshness')
    expect(screen.getByText('Domain registration')).toBeInTheDocument()
    expect(screen.getByText('Not observed yet', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('Seen by dnsx', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('fresh for 24 h', { exact: false })).toBeInTheDocument()
    expect(screen.getByText('fresh for 7 days', { exact: false })).toBeInTheDocument()
    expect(screen.getAllByText('Stale').length).toBeGreaterThanOrEqual(2) // asset badge + http
    expect(screen.getByText('Never observed')).toBeInTheDocument()
    const status = screen.getByTestId('asset-enrichment-status')
    expect(status).toHaveTextContent('Enriched')
    expect(screen.getByRole('link', { name: 'View run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=run-1'
    )
  })

  it('fetches nothing without assets:read', () => {
    perms = []
    wrap(<AssetFreshnessSection assetId="a1" />)
    expect(api.get).not.toHaveBeenCalled()
  })
})
