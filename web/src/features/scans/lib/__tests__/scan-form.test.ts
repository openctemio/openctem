import { describe, expect, it } from 'vitest'

import type { ScanConfig } from '@/lib/api/scan-types'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import {
  basicInfoError,
  formDataToCreateRequest,
  formDataToUpdateRequest,
  frequencyToScheduleType,
  scanConfigToFormData,
  scheduleTypeToFrequency,
} from '../scan-form'

const form = (over: Partial<NewScanFormData> = {}): NewScanFormData => ({
  ...DEFAULT_NEW_SCAN,
  name: '  Weekly SCA  ',
  scannerName: 'trivy',
  targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: ['example.com'] },
  ...over,
})

const config = (over: Partial<ScanConfig> = {}) =>
  ({
    id: 'c1',
    name: 'Weekly SCA',
    scan_type: 'single',
    scanner_name: 'trivy',
    scanner_config: { severity: 'high', token: '********' },
    schedule_type: 'weekly',
    schedule_day: 1,
    schedule_time: '02:00',
    targets_per_job: 20,
    timeout_seconds: 1800,
    max_retries: 2,
    retry_backoff_seconds: 120,
    sensor_preference: 'tenant',
    targets: ['example.com'],
    asset_group_ids: ['g1'],
    ...over,
  }) as unknown as ScanConfig

describe('schedule mapping', () => {
  it('maps API schedule types to form frequencies and back', () => {
    for (const f of ['daily', 'weekly', 'monthly'] as const) {
      expect(scheduleTypeToFrequency(f)).toBe(f)
      expect(frequencyToScheduleType(f)).toBe(f)
    }
    expect(scheduleTypeToFrequency('manual')).toBe('once')
    expect(scheduleTypeToFrequency(undefined)).toBe('once')
    expect(scheduleTypeToFrequency('nonsense')).toBe('once')
    expect(frequencyToScheduleType('once')).toBe('manual')
    expect(frequencyToScheduleType(undefined)).toBe('manual')
  })
})

describe('basicInfoError', () => {
  it('needs a name, and a scanner (single) or a pipeline (workflow)', () => {
    expect(basicInfoError(form({ name: ' ' }))).toMatch(/name/)
    expect(basicInfoError(form({ scannerName: '' }))).toMatch(/scanner/)
    expect(basicInfoError(form({ mode: 'workflow', scannerName: '' }))).toMatch(/workflow/)
    expect(basicInfoError(form({ mode: 'workflow', workflowId: 'p1' }))).toBeNull()
    expect(basicInfoError(form())).toBeNull()
  })
})

describe('formDataToCreateRequest', () => {
  it('sends the chosen scanner, not a hardcoded one', () => {
    const req = formDataToCreateRequest(form({ scannerName: 'semgrep' }))
    expect(req.scan_type).toBe('single')
    expect(req.scanner_name).toBe('semgrep')
    expect(req.pipeline_id).toBeUndefined()
    expect(req.name).toBe('Weekly SCA')
  })

  it('sends no scanner_config keys nothing reads (options, intensity)', () => {
    const req = formDataToCreateRequest(form())
    expect(req.scanner_config).toBeUndefined()
  })

  it('sends the real pipeline id in workflow mode, and no scanner', () => {
    const req = formDataToCreateRequest(form({ mode: 'workflow', workflowId: 'p-123' }))
    expect(req.scan_type).toBe('workflow')
    expect(req.pipeline_id).toBe('p-123')
    expect(req.scanner_name).toBeUndefined()
  })

  it('combines asset groups, resolved assets and custom targets', () => {
    const req = formDataToCreateRequest(
      form({
        targets: {
          type: 'asset_groups',
          assetGroupIds: ['g1', 'g2'],
          assetIds: ['a1', 'a2'],
          assetNames: { a1: 'api.example.com' },
          customTargets: ['10.0.0.1'],
        },
      })
    )
    expect(req.asset_group_ids).toEqual(['g1', 'g2'])
    expect(req.asset_group_id).toBe('g1')
    expect(req.targets).toEqual(['api.example.com', '10.0.0.1'])
  })

  it('carries the schedule only when not run immediately', () => {
    const now = formDataToCreateRequest(form())
    expect(now.schedule_type).toBe('manual')
    expect(now.schedule_time).toBeUndefined()
    const weekly = formDataToCreateRequest(
      form({
        schedule: { runImmediately: false, frequency: 'weekly', dayOfWeek: 3, time: '04:00' },
      })
    )
    expect(weekly).toMatchObject({
      schedule_type: 'weekly',
      schedule_day: 3,
      schedule_time: '04:00',
    })
  })
})

describe('scanConfigToFormData + formDataToUpdateRequest (Edit)', () => {
  it('starts from the configuration, scanner included', () => {
    const f = scanConfigToFormData(config())
    expect(f).toMatchObject({
      name: 'Weekly SCA',
      mode: 'single',
      scannerName: 'trivy',
      maxConcurrent: 20,
      timeoutSeconds: 1800,
      maxRetries: 2,
      retryBackoffSeconds: 120,
      sensorPreference: 'tenant',
    })
    expect(f.schedule).toEqual({
      runImmediately: false,
      frequency: 'weekly',
      dayOfWeek: 1,
      time: '02:00',
    })
  })

  it('saving unchanged keeps the scanner (no reset to nuclei)', () => {
    const c = config()
    const req = formDataToUpdateRequest(scanConfigToFormData(c), c, { canSetZone: true })
    expect(req.scanner_name).toBe('trivy')
  })

  it('sends scanner_config back as stored, without wizard-only keys', () => {
    const c = config()
    const req = formDataToUpdateRequest(scanConfigToFormData(c), c, { canSetZone: true })
    expect(req.scanner_config).toEqual({ severity: 'high', token: '********' })
  })

  it('changes the scanner when the user picks another', () => {
    const c = config()
    const req = formDataToUpdateRequest({ ...scanConfigToFormData(c), scannerName: 'nuclei' }, c, {
      canSetZone: true,
    })
    expect(req.scanner_name).toBe('nuclei')
  })

  it('only someone who can see zones may change the zone', () => {
    const c = config({ scan_zone_id: 'z1' } as Partial<ScanConfig>)
    expect(
      formDataToUpdateRequest(scanConfigToFormData(c), c, { canSetZone: true }).scan_zone_id
    ).toBe('z1')
    expect(
      'scan_zone_id' in formDataToUpdateRequest(scanConfigToFormData(c), c, { canSetZone: false })
    ).toBe(false)
  })

  it('keeps a workflow scan on its pipeline', () => {
    const c = config({
      scan_type: 'workflow',
      scanner_name: undefined,
      pipeline_id: 'p9',
    } as Partial<ScanConfig>)
    const f = scanConfigToFormData(c)
    expect(f.mode).toBe('workflow')
    const req = formDataToUpdateRequest(f, c, { canSetZone: false })
    expect(req.pipeline_id).toBe('p9')
    expect(req.scanner_name).toBeUndefined()
  })
})

describe('a Tenable.sc scan (scanner tenable_sc)', () => {
  const tenable = (cfg: Record<string, unknown> | undefined) =>
    form({ scannerName: 'tenable_sc', scannerConfig: cfg })

  it('needs the connector, a policy and a repository', () => {
    expect(basicInfoError(tenable(undefined))).toMatch(/connector/)
    expect(basicInfoError(tenable({ integration_id: 'i1', repository_id: 5 }))).toMatch(/policy/)
    expect(basicInfoError(tenable({ integration_id: 'i1', policy_id: 7 }))).toMatch(/repository/)
    expect(
      basicInfoError(tenable({ integration_id: 'i1', policy_id: 7, repository_id: 5 }))
    ).toBeNull()
  })

  it('sends its scanner_config on create; other scanners send none', () => {
    const req = formDataToCreateRequest(
      tenable({ integration_id: 'i1', policy_id: 7, repository_id: 5, zone_id: 0 })
    )
    expect(req.scanner_name).toBe('tenable_sc')
    expect(req.scanner_config).toEqual({ integration_id: 'i1', policy_id: 7, repository_id: 5 })
    expect(formDataToCreateRequest(form()).scanner_config).toBeUndefined()
  })

  it('round-trips through edit, keeping keys it does not manage', () => {
    const stored = config({
      scanner_name: 'tenable_sc',
      scanner_config: {
        integration_id: 'i1',
        policy_id: 7,
        repository_id: 5,
        max_scan_seconds: 3600,
      },
    })
    const f = scanConfigToFormData(stored)
    expect(f.scannerConfig).toMatchObject({ policy_id: 7 })
    const changed = { ...f, scannerConfig: { ...f.scannerConfig, policy_id: 8 } }
    const req = formDataToUpdateRequest(changed, stored, { canSetZone: false })
    expect(req.scanner_config).toEqual({
      integration_id: 'i1',
      policy_id: 8,
      repository_id: 5,
      max_scan_seconds: 3600,
    })
  })
})
