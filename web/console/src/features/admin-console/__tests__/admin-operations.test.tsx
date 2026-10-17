import { describe, it, expect } from 'vitest'
import {
  compareVersions,
  schemaState,
  sensorTransportView,
  summarizeSensors,
} from '../lib/operations'
import { buildAttention } from '../lib/attention'
import type { AdminOperations, AdminOverview } from '../types'

function ops(patch: Partial<AdminOperations> = {}): AdminOperations {
  return {
    build: { version: 'v0.10.0', channel: 'release' },
    schema: { applied: 1347, shipped: 1347, dirty: false, known: true },
    database: {
      ok: true,
      configured: true,
      latency_ms: 1,
      open_connections: 2,
      in_use: 1,
      idle: 1,
      max_open: 25,
      wait_count: 0,
    },
    redis: { ok: true, configured: true, latency_ms: 1 },
    queues: {
      commands_pending: 0,
      commands_running: 0,
      command_oldest_pending_seconds: 0,
      scan_runs_open: 0,
      scan_runs_past_deadline: 0,
      outbox_pending: 0,
      outbox_failed: 0,
      outbox_dead: 0,
      outbox_oldest_pending_seconds: 0,
    },
    sensors: [],
    controllers: [],
    checked_at: '2026-10-08T12:00:00Z',
    ...patch,
  }
}

describe('compareVersions', () => {
  it('orders by the numeric core', () => {
    expect(compareVersions('v0.9.2', '0.10.0')).toBe(-1)
    expect(compareVersions('0.10.0-rc.1', 'v0.10.0')).toBe(0)
    expect(compareVersions('1.0', '0.99.9')).toBe(1)
  })
})

describe('summarizeSensors', () => {
  it('splits platform and customer sensors and flags SDKs below the minimum', () => {
    const s = summarizeSensors(
      ops({
        sdk_advisories: ['v0.8.4'],
        sensors: [
          { platform: true, health: 'online', sdk_version: 'v0.10.1', count: 2 },
          { platform: true, health: 'stale', sdk_version: 'v0.8.4', count: 1 },
          { platform: false, health: 'online', sdk_version: 'v0.10.1', count: 5 },
          { platform: false, health: 'late', count: 1 },
        ],
      })
    )
    expect(s.platform).toEqual({ total: 3, online: 2, unhealthy: 1 })
    expect(s.customer).toEqual({ total: 6, online: 5, unhealthy: 0 })
    expect(s.versions).toEqual([
      { version: 'v0.10.1', count: 7, advisory: false },
      { version: 'v0.8.4', count: 1, advisory: true },
      { version: 'unknown', count: 1, advisory: false },
    ])
  })
})

describe('schemaState', () => {
  it('names drift', () => {
    expect(schemaState(ops())).toBe('ok')
    expect(
      schemaState(ops({ schema: { applied: 1300, shipped: 1347, dirty: false, known: true } }))
    ).toBe('behind')
    expect(
      schemaState(ops({ schema: { applied: 1350, shipped: 1347, dirty: false, known: true } }))
    ).toBe('ahead')
    expect(
      schemaState(ops({ schema: { applied: 1347, shipped: 1347, dirty: true, known: true } }))
    ).toBe('dirty')
    expect(
      schemaState(ops({ schema: { applied: 0, shipped: 0, dirty: false, known: false } }))
    ).toBe('unknown')
  })
})

describe('attention links platform problems to Operations', () => {
  it('sends schema and queue problems to /operations', () => {
    const o: AdminOverview = {
      organizations: { total: 1, without_owner: 0, without_owner_sample: [] },
      security: {
        break_glass_sign_ins_7d: 0,
        failed_admin_actions_24h: 0,
        break_glass_tests_overdue: 0,
      },
      platform: {
        schema_version: 1300,
        schema_shipped: 1347,
        schema_dirty: false,
        schema_known: true,
        platform_sensors: { total: 0, online: 0, offline: 0 },
        commands_pending: 0,
        command_oldest_pending_seconds: 0,
        scan_runs_past_deadline: 2,
        outbox_failed: 0,
        outbox_dead: 1,
      },
      generated_at: '2026-10-08T12:00:00Z',
    }
    const items = buildAttention(o, 'readonly')
    expect(items.map((i) => i.href)).toEqual(['/operations', '/operations', '/operations'])
  })
})

describe('sensorTransportView', () => {
  const probeReasons = [
    'no_public_host',
    'sensor_ca_unavailable',
    'listener_failed',
    'dns_failed',
    'unreachable',
    'foreign_certificate',
    'handshake_failed',
    'http2_refused',
  ]

  it('is absent when the API does not report it', () => {
    expect(sensorTransportView(undefined)).toBeNull()
  })

  it('has nothing to say while gRPC is offered or the first probe runs', () => {
    expect(
      sensorTransportView({ mode: 'auto', grpc: { state: 'advertised', endpoint: 'h:443' } })
    ).toEqual({ binding: 'grpc' })
    expect(sensorTransportView({ mode: 'auto', grpc: { state: 'pending' } })).toEqual({
      binding: 'pending',
    })
    expect(
      sensorTransportView({ mode: 'auto', grpc: { state: 'unavailable', reason: 'probe_pending' } })
    ).toEqual({ binding: 'pending' })
  })

  it('maps every probe reason to its own note and keeps the code', () => {
    for (const reason of probeReasons) {
      expect(sensorTransportView({ mode: 'auto', grpc: { state: 'unavailable', reason } })).toEqual(
        { binding: 'https', noteKey: `admin.ops.transport.reason.${reason}`, reason }
      )
    }
  })

  it('falls back to a generic note for an unknown reason', () => {
    expect(
      sensorTransportView({ mode: 'auto', grpc: { state: 'unavailable', reason: 'new_reason' } })
    ).toEqual({
      binding: 'https',
      noteKey: 'admin.ops.transport.reason.other',
      reason: 'new_reason',
    })
  })

  it('says protocol v3 is off when the API serves v2 only', () => {
    expect(
      sensorTransportView({ mode: 'off', grpc: { state: 'unavailable', reason: 'transport_off' } })
    ).toEqual({
      binding: 'off',
      noteKey: 'admin.ops.transport.reason.transport_off',
      reason: 'transport_off',
    })
  })

  it('has every note in English and Vietnamese', async () => {
    const en = (await import('@/lib/i18n/dictionaries/en/admin.json')).default as Record<
      string,
      string
    >
    const vi = (await import('@/lib/i18n/dictionaries/vi/admin.json')).default as Record<
      string,
      string
    >
    for (const r of [...probeReasons, 'transport_off', 'probe_pending', 'other']) {
      const key = `admin.ops.transport.reason.${r}`
      expect(en[key], key).toBeTruthy()
      expect(vi[key], key).toBeTruthy()
    }
  })
})
