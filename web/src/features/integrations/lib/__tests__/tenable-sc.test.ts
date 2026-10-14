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
  readConnectorSettings,
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
