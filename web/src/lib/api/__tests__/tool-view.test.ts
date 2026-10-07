import { describe, expect, it, vi, beforeEach } from 'vitest'

const getMock = vi.fn()
vi.mock('../client', () => ({
  get: (url: string) => getMock(url),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
  patch: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: null }) }))

import { fetchAllTools, toAvailability, toToolsWithConfig } from '../tool-hooks'
import type { ToolListResponse, ToolView, ToolAvailabilityInfo } from '../tool-types'

const avail = (status: ToolAvailabilityInfo['status']): ToolAvailabilityInfo => ({
  enabled: status !== 'disabled',
  status,
  sensors_online: 0,
  sensors_total: 0,
  sensors_excluded: 0,
  sensors: [],
  versions: [],
  update_available: false,
  content: [],
})

const tool = (name: string, over: Partial<ToolView> = {}): ToolView =>
  ({ id: name, name, display_name: name, is_active: true, source: 'platform', ...over }) as ToolView

const page = (items: ToolView[], p: number, totalPages: number): ToolListResponse => ({
  items,
  total: 3,
  page: p,
  per_page: 2,
  total_pages: totalPages,
  meta: { omitted_includes: [] },
})

describe('tool view adapters', () => {
  beforeEach(() => getMock.mockReset())

  it('reads every page of the list', async () => {
    getMock
      .mockResolvedValueOnce(page([tool('a'), tool('b')], 1, 2))
      .mockResolvedValueOnce(page([tool('c')], 2, 2))
    const all = await fetchAllTools('/api/v1/tools?include=settings')
    expect(getMock.mock.calls.map((c) => c[0])).toEqual([
      '/api/v1/tools?include=settings&page=1',
      '/api/v1/tools?include=settings&page=2',
    ])
    expect(all.items.map((t) => t.name)).toEqual(['a', 'b', 'c'])
  })

  it('maps settings and availability for the workflow pickers', () => {
    const resp = page(
      [
        tool('on', {
          settings: { is_enabled: true, config: {}, effective_config: { x: 1 } },
          availability: avail('ready'),
        }),
        tool('off', {
          settings: { is_enabled: false, config: {}, effective_config: {} },
          availability: avail('no_sensor'),
        }),
        // Settings and availability left out (no permission): unknown.
        tool('unknown'),
      ],
      1,
      1
    )
    const items = toToolsWithConfig(resp).items
    expect(items.map((i) => [i.tool.name, i.is_enabled, i.is_available])).toEqual([
      ['on', true, true],
      ['off', false, false],
      ['unknown', null, null],
    ])
    expect(items[0].effective_config).toEqual({ x: 1 })
  })

  it('joins catalog tools and unlisted tools into the availability view', () => {
    const resp: ToolListResponse = {
      ...page([tool('nuclei', { availability: avail('ready') })], 1, 1),
      availability: {
        summary: { ready: 1, no_sensor: 0, offline_only: 0, outdated: 0, disabled: 1 },
        computed_at: '2026-10-07T00:00:00Z',
        unlisted: [{ ...avail('disabled'), name: 'mystery' }],
      },
    }
    const view = toAvailability(resp)
    expect(view?.items.map((i) => [i.name, i.in_catalog, i.tool?.name ?? null])).toEqual([
      ['nuclei', true, 'nuclei'],
      ['mystery', false, null],
    ])
    expect(toAvailability(page([tool('x')], 1, 1))).toBeUndefined()
  })
})
