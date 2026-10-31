import { describe, expect, it, vi } from 'vitest'

import {
  applySensorChanges,
  fetchSensorFleet,
  type SensorFleet,
  type SensorFleetChanges,
} from '../sensor-hooks'
import type { Sensor, SensorListResponse } from '../sensor-types'

vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: null }) }))

const s = (id: string, name = id) => ({ id, name }) as Sensor
const stats = { total: 2 } as SensorFleetChanges['stats']

describe('applySensorChanges', () => {
  it('a full answer replaces the fleet', () => {
    const next = applySensorChanges(undefined, {
      items: [s('a'), s('b')],
      total: 2,
      page: 1,
      per_page: 2,
      full: true,
      cursor: 'c1',
      stats,
    })
    expect(next?.items.map((x) => x.id)).toEqual(['a', 'b'])
    expect(next?.cursor).toBe('c1')
    expect(next?.stats).toBe(stats)
  })

  it('a partial answer replaces only the changed sensors, in place', () => {
    const prev: SensorFleet = {
      items: [s('a'), s('b'), s('c')],
      total: 3,
      page: 1,
      per_page: 3,
      cursor: 'c1',
    }
    const next = applySensorChanges(prev, {
      items: [s('b', 'renamed')],
      total: 3,
      page: 1,
      per_page: 1,
      full: false,
      cursor: 'c2',
      stats,
    })
    expect(next?.items.map((x) => x.name)).toEqual(['a', 'renamed', 'c'])
    expect(next?.items[0]).toBe(prev.items[0])
    expect(next?.cursor).toBe('c2')
  })

  it('nothing changed: the same sensor array (no re-render downstream)', () => {
    const prev: SensorFleet = { items: [s('a')], total: 1, page: 1, per_page: 1, cursor: 'c1' }
    const next = applySensorChanges(prev, {
      items: [],
      total: 1,
      page: 1,
      per_page: 0,
      full: false,
      cursor: 'c1',
    })
    expect(next?.items).toBe(prev.items)
  })

  it('a partial answer with nothing to apply it to is refused', () => {
    expect(
      applySensorChanges(undefined, { items: [], total: 1, page: 1, per_page: 0, full: false })
    ).toBeUndefined()
  })
})

describe('fetchSensorFleet', () => {
  const noPages = vi.fn(async (): Promise<SensorListResponse> => {
    throw new Error('no page read expected')
  })

  it('sends the previous cursor and applies the changes: one request per refresh', async () => {
    const getChanges = vi.fn(async (): Promise<SensorFleetChanges> => ({
      items: [s('a', 'new')],
      total: 2,
      page: 1,
      per_page: 1,
      full: false,
      cursor: 'c2',
      stats,
    }))
    const prev: SensorFleet = {
      items: [s('a'), s('b')],
      total: 2,
      page: 1,
      per_page: 2,
      cursor: 'c1',
    }
    const fleet = await fetchSensorFleet(getChanges, noPages, prev)
    expect(getChanges).toHaveBeenCalledTimes(1)
    expect(getChanges).toHaveBeenCalledWith('c1')
    expect(fleet.items.map((x) => x.name)).toEqual(['new', 'b'])
    expect(fleet.stats).toBe(stats)
  })

  it('starts with an empty cursor (snapshot)', async () => {
    const getChanges = vi.fn(async (): Promise<SensorFleetChanges> => ({
      items: [s('a')],
      total: 1,
      page: 1,
      per_page: 1,
      full: true,
      cursor: 'c1',
    }))
    await fetchSensorFleet(getChanges, noPages, undefined)
    expect(getChanges).toHaveBeenCalledWith('')
  })

  it('falls back to every page against an API without poll mode', async () => {
    const getChanges = vi.fn(async (): Promise<SensorFleetChanges> => ({
      items: [s('a')],
      total: 1,
      page: 1,
      per_page: 20,
    }))
    const getPage = vi.fn(async (page: number): Promise<SensorListResponse> => ({
      items: [s('a'), s('b')],
      total: 2,
      page,
      per_page: 100,
    }))
    const fleet = await fetchSensorFleet(getChanges, getPage, undefined)
    expect(getPage).toHaveBeenCalledWith(1)
    expect(fleet.items).toHaveLength(2)
  })
})
