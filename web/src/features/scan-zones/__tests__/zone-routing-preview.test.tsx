import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import type { ScanZonePreview } from '@/lib/api/scan-zone-types'

const perms = vi.hoisted(() => ({ granted: new Set<string>(['sensors:zones:read']) }))
const api = vi.hoisted(() => ({ previewScanZoneRouting: vi.fn() }))

vi.mock('@/lib/permissions', () => ({
  Permission: { ScanZonesRead: 'sensors:zones:read', SensorsRead: 'sensors:read' },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => api)
vi.mock('@/lib/api/sensor-hooks', () => ({
  useSensors: () => ({ data: { items: [] }, isLoading: false }),
  useAllSensors: () => ({ data: { items: [] }, isLoading: false }),
}))

import { ScanRoutingSection, previewSkipGroups } from '../components/zone-routing-preview'

const base: ScanZonePreview = {
  zones_enabled: false,
  routed: false,
  resolved_targets: 556,
  excluded_targets: 0,
  excluded: [],
  targets: [],
  zones: [],
  unzoned_targets: 0,
  uncovered_targets: 0,
  jobs: 1,
  targets_per_job: 10,
  warnings: [],
}

const request = {
  targets: ['*.example.com'],
  asset_group_ids: [],
  scan_type: 'single' as const,
  scanner_name: 'nuclei',
}

describe('ScanRoutingSection', () => {
  beforeEach(() => api.previewScanZoneRouting.mockReset())

  it('without scan zones: what the scan covers, with no zone picker and no zone wording', async () => {
    api.previewScanZoneRouting.mockResolvedValue({
      ...base,
      will_scan: 121,
      skipped_total: 435,
      skipped: [
        { reason: 'not_resolving', tone: 'info', count: 434, targets: ['gone.example.com'] },
        { reason: 'excluded', tone: 'info', count: 1, targets: ['old.example.com'] },
      ],
    })
    render(<ScanRoutingSection zones={[]} value={null} onChange={() => {}} request={request} />)
    expect(await screen.findByTestId('outcome-will-scan', {}, { timeout: 2000 })).toHaveTextContent(
      '121'
    )
    expect(screen.getByTestId('outcome-skipped')).toHaveTextContent('435')
    const section = screen.getByTestId('new-scan-routing')
    expect(within(section).queryByText(/zone/i)).not.toBeInTheDocument()
    expect(section.querySelector('.text-destructive')).toBeNull()
  })

  it('with zones that take a share: the picker and the zone table', async () => {
    api.previewScanZoneRouting.mockResolvedValue({
      ...base,
      zones_enabled: true,
      routed: true,
      will_scan: 2,
      skipped: [],
      unzoned_targets: 1,
      zones: [
        { zone_id: 'z1', zone_name: 'HQ', targets: 1, jobs: 1, queued_jobs: 0, sensor_ids: [] },
      ],
    })
    render(
      <ScanRoutingSection
        zones={[
          {
            id: 'z1',
            tenant_id: 't',
            name: 'HQ',
            description: '',
            is_default: false,
            ranges: [],
            sensor_ids: [],
            created_at: '',
            updated_at: '',
          },
        ]}
        value={null}
        onChange={() => {}}
        // A different draft: the preview is cached per request.
        request={{ ...request, targets: ['10.1.0.1', 'www.example.com'] }}
      />
    )
    expect(await screen.findByTestId('zone-share-table', {}, { timeout: 2000 })).toBeInTheDocument()
    expect(screen.getByLabelText('Scan zone')).toBeInTheDocument()
    expect(screen.getByText('1 public target goes to any of your sensors')).toBeInTheDocument()
    expect(screen.getByText('Every target will be scanned.')).toBeInTheDocument()
  })
})

describe('previewSkipGroups', () => {
  it('groups an older API answer from its rows', () => {
    const got = previewSkipGroups({
      ...base,
      resolved_targets: 5,
      uncovered_targets: 3,
      excluded_targets: 1,
      excluded: ['x.example.com'],
      targets: [
        { target: 'a.example.com', status: 'uncovered', kind: 'unresolved' },
        { target: 'b.example.com', status: 'uncovered', kind: 'unresolved' },
        { target: '10.0.0.1', status: 'uncovered' },
        { target: 'c.example.com', status: 'unzoned' },
      ],
    })
    expect(got.willScan).toBe(2)
    expect(got.groups.map((g) => [g.reason, g.tone, g.count])).toEqual([
      ['unresolved', 'info', 2],
      ['other', 'warning', 1],
      ['excluded', 'info', 1],
    ])
  })
})
