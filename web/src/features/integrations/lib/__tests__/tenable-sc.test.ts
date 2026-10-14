import { describe, expect, it } from 'vitest'

import en from '@/lib/i18n/dictionaries/en/tenableSc.json'
import vi from '@/lib/i18n/dictionaries/vi/tenableSc.json'

import type { Integration } from '@/features/integrations/types/integration.types'
import type { Sensor } from '@/lib/api/sensor-types'
import {
  DEFAULT_CONNECTOR_SETTINGS,
  connectorConfig,
  connectorSensorOptions,
  connectorSettingsError,
  coverageNumbers,
  isTenableSCConnector,
  isTenableSCFinding,
  isTenableScannableAssetType,
  readConnectorSettings,
  rotationProgress,
  tenableSCConnectors,
  readTenableScanConfig,
  readTenableSync,
  tenableScanConfigError,
  tenableScanConfigToApi,
} from '../tenable-sc'

function integration(config: Record<string, unknown>, sync?: Record<string, unknown>): Integration {
  return {
    id: 'i1',
    tenant_id: 't1',
    name: 'Tenable.sc',
    category: 'security',
    provider: 'tenable',
    status: 'connected',
    auth_type: 'api_key',
    config,
    metadata: sync ? { tenable_sync: sync } : {},
  } as unknown as Integration
}

const connectorCfg = {
  engine: 'tenable_sc',
  execution_mode: 'sensor',
  sensor_id: 's1',
  instance: 'sc-prod',
}

describe('readTenableSync', () => {
  it('reads the state, catalog and counts the API keeps', () => {
    const s = readTenableSync(
      integration(connectorCfg, {
        last_successful_sync: '2026-10-04T10:00:00Z',
        last_outcome: 'completed',
        licensed_ips: 1000,
        active_ips: '420',
        open: 80,
        catalog: {
          policies: [{ id: 1000003, name: 'Basic Network Scan' }, { id: -1 }, 'junk'],
          scan_repositories: [{ id: 5 }],
        },
        coverage_command_id: 'c9',
      })
    )
    expect(s.licensedIPs).toBe(1000)
    expect(s.activeIPs).toBe(420)
    expect(s.lastOutcome).toBe('completed')
    expect(s.catalog?.policies).toEqual([{ id: 1000003, name: 'Basic Network Scan' }])
    expect(s.catalog?.scanRepositories).toEqual([{ id: 5, name: '#5' }])
    expect(s.coverageCommandId).toBe('c9')
  })

  it('tolerates missing or hostile metadata', () => {
    expect(readTenableSync(undefined).catalog).toBeNull()
    const bad = {
      ...integration(connectorCfg),
      metadata: { tenable_sync: 'nope' },
    } as unknown as Integration
    expect(readTenableSync(bad).licensedIPs).toBe(0)
  })
})

describe('isTenableSCConnector', () => {
  it('accepts only the sensor connector', () => {
    expect(isTenableSCConnector(integration(connectorCfg))).toBe(true)
    expect(isTenableSCConnector(integration({ engine: 'nessus_pro' }))).toBe(false)
    expect(
      isTenableSCConnector(integration({ engine: 'tenable_sc', execution_mode: 'direct' }))
    ).toBe(false)
    expect(
      isTenableSCConnector({ ...integration(connectorCfg), provider: 'wiz' } as Integration)
    ).toBe(false)
  })
})

describe('connector settings', () => {
  it('round-trips through the config, always in sensor mode, never with credentials', () => {
    const cfg = connectorConfig(
      {
        ...DEFAULT_CONNECTOR_SETTINGS,
        sensorId: 's1',
        instance: 'sc-prod',
        minSeverity: 0,
        coverageEnabled: true,
        coveragePolicyId: 7,
        coverageRepositoryId: 5,
        safetyMargin: 2,
      },
      { batch_size: 99, keep_me: 'x' }
    )
    expect(cfg).toMatchObject({
      engine: 'tenable_sc',
      execution_mode: 'sensor',
      min_severity: 0,
      keep_me: 'x',
    })
    expect(cfg).not.toHaveProperty('batch_size')
    expect(Object.keys(cfg)).not.toContain('access_key')
    const back = readConnectorSettings(integration(cfg))
    expect(back.minSeverity).toBe(0)
    expect(back.coveragePolicyId).toBe(7)
    expect(back.coverageEnabled).toBe(true)
  })

  it('keeps the connector assets in scope by default, and the switch off when set', () => {
    expect(readConnectorSettings(integration({})).assetsInScope).toBe(true)
    const off = connectorConfig({
      ...DEFAULT_CONNECTOR_SETTINGS,
      sensorId: 's1',
      assetsInScope: false,
    })
    expect(off.assets_in_scope).toBe(false)
    expect(readConnectorSettings(integration(off)).assetsInScope).toBe(false)
  })

  it('reports the first problem', () => {
    const ok = { ...DEFAULT_CONNECTOR_SETTINGS, sensorId: 's1' }
    expect(connectorSettingsError(ok)).toBeNull()
    expect(connectorSettingsError({ ...ok, sensorId: '' })?.fallback).toMatch(/sensor/)
    expect(connectorSettingsError({ ...ok, instance: '../x' })?.fallback).toMatch(/Instance/)
    expect(connectorSettingsError({ ...ok, coverageEnabled: true })?.fallback).toMatch(/policy/)
  })
})

describe('connectorSensorOptions', () => {
  const sensor = (id: string, extra: Partial<Sensor>): Sensor =>
    ({ id, name: id, status: 'active', ...extra }) as unknown as Sensor
  it('keeps own active sensors, those running the connector first', () => {
    const out = connectorSensorOptions([
      sensor('b', {}),
      sensor('a', {
        reported: { tools: [{ name: 'tenable_sc', installed: true }] } as Sensor['reported'],
      }),
      sensor('off', { status: 'disabled' }),
    ])
    expect(out.map((o) => [o.sensor.id, o.runsConnector])).toEqual([
      ['a', true],
      ['b', false],
    ])
  })
})

describe('coverageNumbers', () => {
  it('sizes the next batch like the API: min(license, cap) - active - margin', () => {
    const n = coverageNumbers(
      integration(
        { ...connectorCfg, coverage_enabled: true, license_cap: 500, safety_margin: 10 },
        {
          licensed_ips: 1000,
          active_ips: 420,
          coverage_command_id: 'c1',
          last_coverage_outcome: 'completed',
        }
      )
    )
    expect(n).toMatchObject({
      enabled: true,
      licensed: 1000,
      limit: 500,
      active: 420,
      headroom: 70,
      batchOpen: true,
    })
  })

  it('is unknown before a sync reported the license, never zero', () => {
    const n = coverageNumbers(integration({ ...connectorCfg, coverage_enabled: true }))
    expect(n.licensed).toBeNull()
    expect(n.headroom).toBeNull()
  })

  it('never goes below zero', () => {
    const n = coverageNumbers(integration(connectorCfg, { licensed_ips: 10, active_ips: 12 }))
    expect(n.headroom).toBe(0)
  })
})

describe('tenable scan config', () => {
  it('validates and converts', () => {
    const c = readTenableScanConfig({ integration_id: 'i1', policy_id: 7, repository_id: '5' })
    expect(tenableScanConfigError(c)).toBeNull()
    expect(tenableScanConfigToApi(c, { zone_id: 3, other: 1 })).toEqual({
      integration_id: 'i1',
      policy_id: 7,
      repository_id: 5,
      other: 1,
    })
    expect(tenableScanConfigError({ ...c, policyId: 0 })?.fallback).toMatch(/policy/)
    expect(tenableScanConfigError({ ...c, integrationId: '' })?.fallback).toMatch(/connector/)
  })
})

describe('validation messages', () => {
  it('carry a tenableSc key present in en and vi, with the English text as fallback', () => {
    const ok = { ...DEFAULT_CONNECTOR_SETTINGS, sensorId: 's1' }
    const messages = [
      connectorSettingsError({ ...ok, sensorId: '' }),
      connectorSettingsError({ ...ok, instance: '../x' }),
      connectorSettingsError({ ...ok, minSeverity: 9 }),
      connectorSettingsError({ ...ok, fullSyncDays: 0 }),
      connectorSettingsError({ ...ok, coverageEnabled: true }),
      connectorSettingsError({ ...ok, rotation: 'aging' }),
      connectorSettingsError({ ...ok, rotationWaitHours: 0 }),
      tenableScanConfigError({ integrationId: '', policyId: 0, repositoryId: 0, zoneId: 0 }),
      tenableScanConfigError({ integrationId: 'i1', policyId: 0, repositoryId: 0, zoneId: 0 }),
      tenableScanConfigError({ integrationId: 'i1', policyId: 1, repositoryId: 0, zoneId: 0 }),
    ]
    for (const m of messages) {
      expect(m).not.toBeNull()
      const key = m!.key as keyof typeof en
      expect(en[key], m!.key).toBe(m!.fallback)
      expect(vi[key as keyof typeof vi], m!.key).toBeTruthy()
    }
  })
})

describe('license rotation settings', () => {
  const ok = { ...DEFAULT_CONNECTOR_SETTINGS, sensorId: 's1' }

  it('defaults to off with a 12 hour wait when the config has none', () => {
    const s = readConnectorSettings(integration(connectorCfg))
    expect(s.rotation).toBe('off')
    expect(s.rotationAcknowledged).toBe(false)
    expect(s.rotationWaitHours).toBe(12)
  })

  it('reads the config keys, tolerating case, strings and unknown modes', () => {
    const s = readConnectorSettings(
      integration({
        ...connectorCfg,
        coverage_rotation: 'Recycle',
        coverage_rotation_acknowledged: 'true',
        coverage_rotation_wait_hours: '24',
      })
    )
    expect(s).toMatchObject({
      rotation: 'recycle',
      rotationAcknowledged: true,
      rotationWaitHours: 24,
    })
    expect(readConnectorSettings(integration({ coverage_rotation: 'wipe' })).rotation).toBe('off')
  })

  it('writes the three keys and round-trips them', () => {
    const cfg = connectorConfig({
      ...ok,
      rotation: 'aging',
      rotationAcknowledged: true,
      rotationWaitHours: 6,
    })
    expect(cfg).toMatchObject({
      coverage_rotation: 'aging',
      coverage_rotation_acknowledged: true,
      coverage_rotation_wait_hours: 6,
    })
    expect(readConnectorSettings(integration(cfg))).toMatchObject({
      rotation: 'aging',
      rotationAcknowledged: true,
      rotationWaitHours: 6,
    })
  })

  it('drops the acknowledgement when rotation is off, so turning it on asks again', () => {
    const cfg = connectorConfig({ ...ok, rotation: 'off', rotationAcknowledged: true })
    expect(cfg.coverage_rotation_acknowledged).toBe(false)
  })

  it('refuses rotation without the acknowledgement and a wait outside 1-72 hours', () => {
    expect(connectorSettingsError({ ...ok, rotation: 'aging' })?.key).toBe(
      'tenableSc.error.rotationNeedsAck'
    )
    expect(connectorSettingsError({ ...ok, rotation: 'recycle' })?.key).toBe(
      'tenableSc.error.rotationNeedsAck'
    )
    expect(
      connectorSettingsError({ ...ok, rotation: 'recycle', rotationAcknowledged: true })
    ).toBeNull()
    for (const h of [0, 73, 1.5]) {
      expect(connectorSettingsError({ ...ok, rotationWaitHours: h })?.key).toBe(
        'tenableSc.error.rotationWaitHours'
      )
    }
    expect(connectorSettingsError({ ...ok, rotationWaitHours: 1 })).toBeNull()
    expect(connectorSettingsError({ ...ok, rotationWaitHours: 72 })).toBeNull()
  })

  it('sizes the next batch with rotation: the last batch leaves the count', () => {
    const cfg = { ...connectorCfg, coverage_enabled: true, safety_margin: 10 }
    const sync = { licensed_ips: 1000, active_ips: 900, last_batch_added: 300 }
    expect(coverageNumbers(integration(cfg, sync)).headroom).toBe(90)
    expect(
      coverageNumbers(
        integration(
          { ...cfg, coverage_rotation: 'aging', coverage_rotation_acknowledged: true },
          sync
        )
      ).headroom
    ).toBe(390)
  })
})

describe('rotationProgress', () => {
  const now = new Date('2026-10-14T10:00:00Z')
  const cfg = {
    ...connectorCfg,
    coverage_rotation: 'recycle',
    coverage_rotation_acknowledged: true,
  }

  it('reads the cycle, its progress and ETA', () => {
    const r = rotationProgress(
      integration(cfg, {
        cycle: 3,
        cycle_assessed: 250,
        cycle_eligible: 1000,
        cycle_eta: '2026-10-20T00:00:00Z',
      }),
      now
    )
    expect(r).toMatchObject({
      rotation: 'recycle',
      cycle: 3,
      assessed: 250,
      eligible: 1000,
      percent: 25,
      eta: '2026-10-20T00:00:00Z',
    })
    expect(r.stalled).toBeUndefined()
  })

  it('says when and why the next batch waits, only while it does', () => {
    const waiting = rotationProgress(
      integration(cfg, {
        next_batch_at: '2026-10-14T12:00:00Z',
        coverage_wait: 'the previous batch failed',
      }),
      now
    )
    expect(waiting.nextBatchAt).toBe('2026-10-14T12:00:00Z')
    expect(waiting.waitReason).toBe('the previous batch failed')
    const past = rotationProgress(
      integration(cfg, { next_batch_at: '2026-10-14T08:00:00Z', coverage_wait: 'x' }),
      now
    )
    expect(past.nextBatchAt).toBeUndefined()
    expect(past.waitReason).toBeUndefined()
  })

  it('reports a stalled rotation and no progress before the first batch', () => {
    const r = rotationProgress(integration(cfg, { rotation_stalled: 'rotation stalled: x' }), now)
    expect(r.stalled).toBe('rotation stalled: x')
    expect(r.cycle).toBe(0)
    expect(r.percent).toBeNull()
  })

  it('never shows more assessed than eligible', () => {
    const r = rotationProgress(
      integration(cfg, { cycle: 1, cycle_assessed: 12, cycle_eligible: 10 }),
      now
    )
    expect(r.assessed).toBe(10)
    expect(r.percent).toBe(100)
  })
})

describe('scan now helpers', () => {
  it('lists only Tenable.sc connectors', () => {
    const conn = integration(connectorCfg)
    const nessus = { ...integration({ engine: 'nessus_pro' }), id: 'i2' } as Integration
    expect(tenableSCConnectors([conn, nessus]).map((i) => i.id)).toEqual(['i1'])
    expect(tenableSCConnectors(undefined)).toEqual([])
  })

  it('offers IP addresses and hosts only', () => {
    expect(isTenableScannableAssetType('ip_address')).toBe(true)
    expect(isTenableScannableAssetType('host')).toBe(true)
    expect(isTenableScannableAssetType('domain')).toBe(false)
    expect(isTenableScannableAssetType(undefined)).toBe(false)
  })

  it('recognises a finding the connector reported', () => {
    expect(isTenableSCFinding({ toolName: 'tenable_sc' })).toBe(true)
    expect(isTenableSCFinding({ source: 'tenable_sc' })).toBe(true)
    expect(isTenableSCFinding({ toolName: 'nuclei' })).toBe(false)
    expect(isTenableSCFinding(undefined)).toBe(false)
  })
})
