import { describe, expect, it } from 'vitest'
import { buildHealthTiles, PLATFORM_SENSORS_URL } from '../lib/installation-health'
import { buildSystemAttention } from '../lib/attention'
import type { AdminOverview, AdminSystem } from '../types'

function overview(sensors = { total: 3, online: 3, offline: 0 }, schema = {}): AdminOverview {
  return {
    platform: {
      schema_version: 20261102020530,
      schema_shipped: 20261102020530,
      schema_dirty: false,
      schema_known: true,
      platform_sensors: sensors,
      ...schema,
    },
  } as unknown as AdminOverview
}

function system(over: Partial<AdminSystem> = {}): AdminSystem {
  return {
    services: [
      { name: 'api', configured: true, ok: true, latency_ms: 0 },
      { name: 'postgres', configured: true, ok: true, latency_ms: 1 },
      { name: 'redis', configured: true, ok: true, latency_ms: 1 },
      { name: 'web', configured: false, ok: false, latency_ms: 0 },
      { name: 'sensors', configured: true, ok: false, latency_ms: 0, code: 'unhealthy', detail: 0 },
    ],
    storage: {
      volumes: [
        {
          name: 'attachments',
          ok: true,
          total_bytes: 100,
          used_bytes: 84,
          free_bytes: 16,
          free_ratio: 0.16,
          level: 1,
        },
        {
          name: 'sensor-ca',
          ok: true,
          total_bytes: 100,
          used_bytes: 84,
          free_bytes: 16,
          free_ratio: 0.16,
          level: 1,
        },
      ],
      database_bytes: 1,
      database_ok: true,
    },
    backup: { reported: false, level: 0 },
    certificates: [],
    version: { running: 'v1' },
    level: 1,
    checked_at: '2026-11-02T00:00:00Z',
    ...over,
  }
}

const tile = (tiles: ReturnType<typeof buildHealthTiles>, key: string) =>
  tiles.find((t) => t.key === key)!

describe('installation health strip', () => {
  it('has five tiles, each with a state in words and a page to open', () => {
    const tiles = buildHealthTiles(overview(), system())
    expect(tiles.map((t) => t.key)).toEqual([
      'services',
      'storage',
      'backup',
      'sensors',
      'database',
    ])
    for (const t of tiles) {
      expect(t.state).toBeTruthy()
      expect(t.href.startsWith('/')).toBe(true)
    }
  })

  it('counts only configured services and leaves sensors to their own tile', () => {
    const ok = tile(buildHealthTiles(overview(), system()), 'services')
    expect(ok).toMatchObject({ tone: 'success', vars: { count: 3 } })
    const down = system()
    down.services[2] = { ...down.services[2], ok: false, code: 'unreachable' }
    expect(tile(buildHealthTiles(overview(), down), 'services')).toMatchObject({
      tone: 'destructive',
      vars: { count: 1, names: 'Redis' },
    })
  })

  it('shows the lowest volume, an unreported backup as muted, and links sensors to their page', () => {
    const tiles = buildHealthTiles(overview({ total: 3, online: 0, offline: 3 }), system())
    expect(tile(tiles, 'storage')).toMatchObject({ tone: 'warning', vars: { percent: 16 } })
    expect(tile(tiles, 'backup')).toMatchObject({ tone: 'muted', state: 'Not reported' })
    expect(tile(tiles, 'sensors')).toMatchObject({
      tone: 'destructive',
      href: PLATFORM_SENSORS_URL,
      vars: { online: 0, total: 3 },
    })
    expect(
      tile(buildHealthTiles(overview({ total: 0, online: 0, offline: 0 }), system()), 'sensors')
        .tone
    ).toBe('muted')
  })

  it('reads the schema state: in sync, behind, stopped midway', () => {
    expect(tile(buildHealthTiles(overview(), system()), 'database').tone).toBe('success')
    expect(
      tile(
        buildHealthTiles(overview(undefined, { schema_version: 1, schema_shipped: 2 }), system()),
        'database'
      )
    ).toMatchObject({ tone: 'destructive', state: 'Behind this release' })
    expect(
      tile(buildHealthTiles(overview(undefined, { schema_dirty: true }), system()), 'database')
        .state
    ).toBe('Migration stopped midway')
  })
})

describe('system attention copy', () => {
  it('says no sensor is online instead of calling sensors a service', () => {
    const items = buildSystemAttention(system())
    expect(items.find((i) => i.id === 'sensors-all-offline')).toMatchObject({
      severity: 'critical',
      title: 'No sensor is online',
    })
    expect(items.some((i) => i.id === 'service-down-sensors')).toBe(false)
  })

  it('reports volumes of one filesystem once, naming them all', () => {
    const storage = buildSystemAttention(system()).filter(
      (i) => i.titleKey === 'admin.attention.storage.title'
    )
    expect(storage).toHaveLength(1)
    expect(storage[0].vars?.name).toBe('attachments, sensor-ca')
  })
})
