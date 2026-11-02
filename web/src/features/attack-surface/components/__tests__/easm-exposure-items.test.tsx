/**
 * Attack surface > Exposure items: the default view asks for open exposures
 * on monitored assets; the severity and type summaries toggle filters; the
 * primary marker and the monitoring state render per row; the group-by-asset
 * view lists assets and a row drills into that asset; the severity cell opens
 * the override dialog only with the permission; the CSV is formula safe;
 * nothing is fetched without the read permissions.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), patch: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ read: true, severity: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  const has = (p: string) =>
    p === actual.Permission.FindingsSeverity ? perms.severity && perms.read : perms.read
  return {
    ...actual,
    usePermissions: () => ({ can: has }),
    useHasPermission: has,
  }
})

const { EASMExposureItems } = await import('../easm-exposure-items')
const lib = await import('../../lib/exposure-items')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const ASSET = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'

const item = (over: Record<string, unknown> = {}) => ({
  id: 'e1',
  asset_id: ASSET,
  asset_name: 'example.com',
  asset_type: 'domain',
  asset_monitoring_state: 'monitored',
  asset_primary: true,
  event_type: 'port_open',
  display_category: 'exposed_ports',
  summary: {
    text: 'Port 6379 (Redis) is open to the internet',
    variant: '',
    args: { port: '6379', service: 'Redis' },
  },
  severity: 'high',
  state: 'active',
  title: 'Open port 6379',
  fingerprint: 'f',
  source: 'nmap',
  first_seen_at: '2026-10-01T00:00:00Z',
  last_seen_at: '2026-10-20T00:00:00Z',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-20T00:00:00Z',
  ...over,
})

beforeEach(() => {
  api.get.mockReset().mockImplementation((url: string) => {
    if (url.includes('/stats')) {
      return Promise.resolve({
        total: 3,
        by_severity: { critical: 1, high: 2 },
        by_category: { exposed_ports: 2, credentials_data: 1 },
        by_state: { active: 3 },
      })
    }
    if (url.includes('/exposures/assets')) {
      return Promise.resolve({
        data: [
          {
            asset_id: ASSET,
            asset_name: 'example.com',
            asset_type: 'domain',
            asset_monitoring_state: 'monitored',
            asset_primary: true,
            total: 2,
            by_severity: { high: 2 },
            top_severity: 'high',
            first_seen_at: '2026-10-01T00:00:00Z',
            last_seen_at: '2026-10-20T00:00:00Z',
          },
        ],
        total: 1,
      })
    }
    return Promise.resolve({
      data: [
        item(),
        item({
          id: 'e2',
          asset_id: undefined,
          asset_name: undefined,
          asset_primary: false,
          title: 'Leaked key',
          asset_monitoring_state: undefined,
        }),
      ],
      total: 2,
    })
  })
  perms.read = true
  perms.severity = true
  window.history.replaceState(null, '', '/attack-surface/exposures')
})

const calls = () => api.get.mock.calls.map(([u]) => decodeURIComponent(String(u)))

describe('EASMExposureItems', () => {
  it('asks for open exposures on monitored assets by default, most severe first', async () => {
    wrap(<EASMExposureItems />)
    expect(await screen.findByText('Open port 6379')).toBeInTheDocument()
    const list = calls().find((u) => u.startsWith('/api/v1/attack-surface/exposures?'))
    expect(list).toContain('state=active,in_progress')
    expect(list).toContain('asset_monitoring_state=monitored')
    expect(list).toContain('sort=-severity')
    expect(screen.getAllByText('Port 6379 (Redis) is open to the internet').length).toBe(2)
    expect(screen.getAllByText('Primary asset').length).toBeGreaterThan(0)
    expect(screen.getByText('No asset')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      `/assets/${ASSET}`
    )
  })

  it('toggles severity and type filters from the summaries', async () => {
    wrap(<EASMExposureItems />)
    await screen.findByText('Open port 6379')
    await userEvent.click(screen.getByRole('button', { name: /Leaked credentials and data/ }))
    await waitFor(() =>
      expect(calls().some((u) => u.includes('category=credentials_data'))).toBe(true)
    )
    // The strips count the set before severity and type are narrowed.
    expect(
      calls()
        .filter((u) => u.includes('/stats'))
        .every((u) => !u.includes('category='))
    ).toBe(true)
  })

  it('lists assets in the group-by-asset view and drills into one', async () => {
    window.history.replaceState(null, '', '/attack-surface/exposures?view=assets')
    wrap(<EASMExposureItems />)
    expect(await screen.findByText('2 High')).toBeInTheDocument()
    await userEvent.click(screen.getByText('2 High'))
    await waitFor(() => expect(calls().some((u) => u.includes(`asset_id=${ASSET}`))).toBe(true))
  })

  it('opens the severity dialog from the severity cell only with the permission', async () => {
    wrap(<EASMExposureItems />)
    await screen.findByText('Open port 6379')
    expect(screen.getAllByRole('button', { name: /Change severity of/ }).length).toBe(2)
  })

  it('shows the severity as text without the permission', async () => {
    perms.severity = false
    wrap(<EASMExposureItems />)
    await screen.findByText('Open port 6379')
    expect(screen.queryByRole('button', { name: /Change severity of/ })).toBeNull()
  })

  it('fetches nothing without the read permissions', async () => {
    perms.read = false
    wrap(<EASMExposureItems />)
    expect(await screen.findByText('Access denied')).toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('exposure items lib', () => {
  it('reads URL params into typed filters and drops unknown values', () => {
    const f = lib.filtersFromParams({
      severity: 'high,bogus',
      state: 'all',
      category: 'dns,nope',
      monitoring: 'monitored',
      primary: 'true',
      asset: 'not-a-uuid',
    })
    expect(f).toEqual({
      q: undefined,
      severities: ['high'],
      states: [],
      categories: ['dns'],
      monitoring: 'monitored',
      primaryOnly: true,
      assetId: undefined,
    })
    expect(lib.exposureItemsUrl(f, { page: 1, perPage: 20 }, '-severity')).toBe(
      '/api/v1/attack-surface/exposures?severity=high&category=dns&asset_monitoring_state=monitored&primary=true&sort=-severity&page=1&per_page=20'
    )
  })

  it('shows produced categories and any category with exposures', () => {
    const keys = lib.visibleCategories({ cloud_storage: 1 })
    expect(keys).toContain('cloud_storage')
    expect(keys).toContain('exposed_ports')
    expect(keys).not.toContain('web_interfaces')
  })

  it('neutralizes formulas in scan-controlled cells', () => {
    const csv = lib.exposureItemsCsv(
      [item({ title: '=HYPERLINK("http://x")', asset_name: '+cmd' }) as never],
      Array.from({ length: 12 }, (_, i) => `h${i}`),
      { category: (c) => c, severity: (s) => s, state: (s) => s, summary: () => '' }
    )
    const line = csv.split('\n')[1]
    expect(line).toContain(`'=HYPERLINK`)
    expect(line).toContain(`'+cmd`)
  })
})
