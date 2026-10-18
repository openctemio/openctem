import { describe, expect, it } from 'vitest'
import { buildSystemAttention, mergeAttention, type AttentionItem } from '../lib/attention'
import type { AdminSystem } from '../types'

const healthy: AdminSystem = {
  services: [{ name: 'api', configured: true, ok: true, latency_ms: 1 }],
  storage: {
    volumes: [
      {
        name: 'data',
        ok: true,
        total_bytes: 100,
        used_bytes: 10,
        free_bytes: 90,
        free_ratio: 0.9,
        level: 0,
      },
    ],
    database_bytes: 1,
    database_ok: true,
  },
  backup: { reported: true, age_seconds: 3600, level: 0 },
  certificates: [{ name: 'sensor-ca', ok: true, expires_in_seconds: 400 * 86400, level: 0 }],
  version: { running: 'v1.0.0' },
  level: 0,
  checked_at: '2026-10-18T00:00:00Z',
}

const ids = (items: AttentionItem[]) => items.map((i) => i.id)

describe('buildSystemAttention', () => {
  it('a healthy, backed-up, current installation needs nothing', () => {
    expect(buildSystemAttention(healthy)).toEqual([])
  })

  it('a volume at 8% free is critical on the overview (it used to stay calm)', () => {
    const sys: AdminSystem = {
      ...healthy,
      storage: {
        ...healthy.storage,
        volumes: [
          {
            name: 'sensor-ca',
            ok: true,
            total_bytes: 200,
            used_bytes: 184,
            free_bytes: 16,
            free_ratio: 0.08,
            level: 2,
          },
        ],
      },
    }
    const [item] = buildSystemAttention(sys)
    expect(item.id).toBe('storage-sensor-ca')
    expect(item.severity).toBe('critical')
    expect(item.vars?.percent).toBe(8)
    expect(item.href).toBe('/system')
  })

  it('reports a down service, a failed backup and an expiring certificate', () => {
    const sys: AdminSystem = {
      ...healthy,
      services: [
        { name: 'redis', configured: true, ok: false, latency_ms: 0, code: 'unreachable' },
      ],
      backup: { reported: true, last_failed: true, level: 2 },
      certificates: [{ name: 'gateway', ok: true, expires_in_seconds: 5 * 86400, level: 1 }],
    }
    expect(ids(buildSystemAttention(sys))).toEqual([
      'service-down-redis',
      'backup-failed',
      'certificate-gateway',
    ])
  })

  it('an unconfigured service is not an alarm; an unreported backup is information', () => {
    const sys: AdminSystem = {
      ...healthy,
      services: [{ name: 'gateway', configured: false, ok: false, latency_ms: 0 }],
      backup: { reported: false, level: 0 },
    }
    const items = buildSystemAttention(sys)
    expect(ids(items)).toEqual(['backup-unknown'])
    expect(items[0].severity).toBe('info')
  })

  it('a release with security advisories is a warning that links to software updates', () => {
    const sys: AdminSystem = {
      ...healthy,
      version: {
        running: 'v1.0.0',
        check: {
          enabled: true,
          configured: true,
          latest: 'v1.0.1',
          update_available: true,
          advisories: 2,
          stale: false,
        },
      },
    }
    const [item] = buildSystemAttention(sys)
    expect(item.id).toBe('update-available')
    expect(item.severity).toBe('warning')
    expect(item.href).toBe('/system/software-updates')
  })

  it('merges overview and system items, most severe first', () => {
    const info: AttentionItem = {
      id: 'i',
      severity: 'info',
      titleKey: '',
      title: '',
      detailKey: '',
      detail: '',
    }
    const crit: AttentionItem = { ...info, id: 'c', severity: 'critical' }
    expect(ids(mergeAttention([info], [crit]))).toEqual(['c', 'i'])
  })
})
