import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { SWRConfig } from 'swr'

import type { ScanZone, ScanZoneCoverage } from '@/lib/api/scan-zone-types'

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const rows = vi.hoisted(() => ({ list: [] as { id: string; name: string; type: string }[] }))

vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsRead: 'assets:read' },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/fetch-all-pages', () => ({
  fetchAllPages: vi.fn(async () => rows.list),
}))

import { ADDRESSES_HREF, MAX_EXAMPLES, ZoneCoverageCard } from '../components/zone-coverage-card'

const zone: ScanZone = {
  id: 'z1',
  tenant_id: 't1',
  name: 'Internal',
  description: '',
  is_default: false,
  ranges: ['10.0.0.0/8'],
  sensor_ids: [],
  created_at: '',
  updated_at: '',
}

// 185 public documentation addresses and two private ones outside every zone.
const publicRows = Array.from({ length: 185 }, (_, i) => ({
  id: `p${i}`,
  name: `198.18.${Math.floor(i / 250)}.${(i % 250) + 1}`,
  type: 'ip_address',
}))
const privateRows = [
  { id: 'v1', name: '192.168.1.10', type: 'ip_address' },
  { id: 'v2', name: '172.16.0.4', type: 'host' },
]

function coverage(over: Partial<ScanZoneCoverage> = {}): ScanZoneCoverage {
  return {
    inventory_addresses: 187,
    in_zones: 0,
    outside_private: 2,
    outside_public: 185,
    has_default_zone: false,
    zones: [
      {
        zone_id: 'z1',
        name: 'Internal',
        is_default: false,
        has_private_range: true,
        assigned_sensors: 0,
        healthy_sensors: 0,
        addresses: 0,
      },
    ],
    warnings: [],
    ...over,
  } as ScanZoneCoverage
}

function renderCard(c = coverage()) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <ZoneCoverageCard coverage={c} zones={[zone]} />
    </SWRConfig>
  )
}

describe('ZoneCoverageCard', () => {
  beforeEach(() => {
    perms.granted = new Set(['assets:read'])
    rows.list = [...publicRows, ...privateRows]
  })

  it('shows labelled counts, a few examples (private first) and a link to the rest', async () => {
    renderCard()
    const counts = screen.getByTestId('zone-outside-counts')
    expect(counts).toHaveTextContent('Private, scans skip these 2')
    expect(counts).toHaveTextContent(
      'Public, any of your sensors scans these (no default zone) 185'
    )

    const list = await screen.findByTestId('zone-outside-list')
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(MAX_EXAMPLES)
    expect(items[0]).toHaveTextContent('192.168.1.10')
    expect(items[0]).toHaveTextContent('private')

    const all = screen.getByTestId('zone-outside-all')
    expect(all).toHaveAttribute('href', ADDRESSES_HREF)
    expect(all).toHaveTextContent('View all 187 addresses in Assets')
    // No long sentence: the old description is gone.
    expect(screen.queryByText(/inventory addresses:/)).toBeNull()
  })

  it('says the warnings it knows in its own words and lists any other one', () => {
    renderCard(
      coverage({
        warnings: [
          { code: 'no_sensors_assigned', zone_id: 'z1', message: 'zone "Internal" has no sensors' },
          { code: 'private_addresses_outside_zones', message: '2 private inventory addresses' },
          { code: 'something_new', message: 'A new coverage note' },
        ],
      })
    )
    const list = screen.getByTestId('zone-coverage-warnings')
    expect(within(list).getAllByRole('listitem')).toHaveLength(1)
    expect(within(list).getByText('A new coverage note')).toBeInTheDocument()
    expect(screen.queryByText(/has no sensors/)).toBeNull()
  })

  it('lists the zone without a sensor', () => {
    renderCard()
    const list = screen.getByTestId('zone-unhealthy-list')
    expect(within(list).getByText('Internal')).toBeInTheDocument()
    expect(within(list).getByText('No sensors assigned')).toBeInTheDocument()
  })

  it('shows only the counts without access to the asset inventory', () => {
    perms.granted = new Set()
    renderCard()
    expect(screen.getByTestId('zone-outside-counts')).toBeInTheDocument()
    expect(screen.queryByTestId('zone-outside-list')).toBeNull()
    expect(screen.queryByTestId('zone-outside-all')).toBeNull()
  })

  it('says every address is inside a zone when none is outside', () => {
    renderCard(coverage({ outside_private: 0, outside_public: 0, in_zones: 187 }))
    expect(screen.getByText('Every inventory address is inside a zone.')).toBeInTheDocument()
    expect(screen.queryByTestId('zone-outside-counts')).toBeNull()
  })
})
