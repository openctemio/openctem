import { describe, expect, it } from 'vitest'

import type { ScanConfig } from '@/lib/api/scan-types'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import {
  basicInfoError,
  optionsError,
  directTargets,
  MAX_DIRECT_TARGETS,
  targetsError,
  formDataToCreateRequest,
  formDataToUpdateRequest,
  frequencyToScheduleType,
  scanConfigToFormData,
  scheduleError,
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
    // "Once" is a real one-off schedule now: it used to be saved as manual,
    // so a scan "scheduled for later, once" never ran.
    expect(scheduleTypeToFrequency('once')).toBe('once')
    expect(frequencyToScheduleType('once')).toBe('once')
    expect(scheduleTypeToFrequency('manual')).toBe('weekly')
    expect(scheduleTypeToFrequency(undefined)).toBe('weekly')
    expect(frequencyToScheduleType(undefined)).toBe('manual')
  })
})

describe('one-off and timezone schedules', () => {
  const later = (schedule: Partial<NewScanFormData['schedule']>) =>
    form({ schedule: { ...DEFAULT_NEW_SCAN.schedule, runImmediately: false, ...schedule } })

  it('sends a once schedule with run_at as the instant in the chosen zone', () => {
    const req = formDataToCreateRequest(
      later({
        frequency: 'once',
        runAtDate: '2030-03-04',
        runAtTime: '22:30',
        timezone: 'Asia/Ho_Chi_Minh',
      })
    )
    expect(req.schedule_type).toBe('once')
    expect(req.run_at).toBe('2030-03-04T15:30:00Z')
    expect(req.timezone).toBe('Asia/Ho_Chi_Minh')
    expect(req.schedule_time).toBeUndefined()
  })

  it('sends the timezone with a recurring schedule (it used to be UTC)', () => {
    const req = formDataToCreateRequest(
      later({ frequency: 'daily', time: '02:00', timezone: 'Europe/Paris' })
    )
    expect(req).toMatchObject({
      schedule_type: 'daily',
      schedule_time: '02:00',
      timezone: 'Europe/Paris',
    })
  })

  it('sends the chosen day of the month (it was always the 1st)', () => {
    const req = formDataToCreateRequest(
      later({ frequency: 'monthly', dayOfMonth: 15, time: '03:00' })
    )
    expect(req.schedule_day).toBe(15)
  })

  it('needs a date and time for a once schedule, at least a minute ahead', () => {
    const now = new Date('2030-03-04T15:00:00Z')
    expect(scheduleError(later({ frequency: 'once' }), { now })).toMatch(/date and time/)
    const past = later({
      frequency: 'once',
      runAtDate: '2030-03-04',
      runAtTime: '14:00',
      timezone: 'UTC',
    })
    expect(scheduleError(past, { now })).toMatch(/minute from now/)
    expect(scheduleError(past, { now, requireFuture: false })).toBeNull()
    const ok = later({
      frequency: 'once',
      runAtDate: '2030-03-04',
      runAtTime: '16:00',
      timezone: 'UTC',
    })
    expect(scheduleError(ok, { now })).toBeNull()
    expect(scheduleError(form(), { now })).toBeNull() // runs now
  })

  it('reads a saved once schedule back in its own zone', () => {
    const data = scanConfigToFormData({
      ...config(),
      schedule_type: 'once',
      schedule_run_at: '2030-03-04T15:30:00Z',
      schedule_timezone: 'Asia/Ho_Chi_Minh',
    })
    expect(data.schedule).toMatchObject({
      runImmediately: false,
      frequency: 'once',
      runAtDate: '2030-03-04',
      runAtTime: '22:30',
      timezone: 'Asia/Ho_Chi_Minh',
    })
    // Sent back unchanged with other edits, the run is the same instant.
    const req = formDataToUpdateRequest(
      data,
      { ...config(), schedule_type: 'once' },
      { canSetZone: false }
    )
    expect(req.run_at).toBe('2030-03-04T15:30:00Z')
  })
})

describe('basicInfoError', () => {
  it('needs a name, and a scanner (single) or a workflow (workflow)', () => {
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
    expect(req.scan_workflow_id).toBeUndefined()
    expect(req.name).toBe('Weekly SCA')
  })

  it('sends no scanner_config keys nothing reads (options, intensity)', () => {
    const req = formDataToCreateRequest(form())
    expect(req.scanner_config).toBeUndefined()
  })

  it('sends the real workflow id in workflow mode, and no scanner', () => {
    const req = formDataToCreateRequest(form({ mode: 'workflow', workflowId: 'p-123' }))
    expect(req.scan_type).toBe('workflow')
    expect(req.scan_workflow_id).toBe('p-123')
    expect(req.scanner_name).toBeUndefined()
  })

  it('sends asset groups, picked assets by id and typed targets', () => {
    const req = formDataToCreateRequest(
      form({
        targets: {
          type: 'asset_groups',
          assetGroupIds: ['g1', 'g2'],
          assetIds: ['a1', 'a2'],
          assetNames: { a1: 'api.example.com' },
          customTargets: ['10.0.0.1', 'Example.COM', 'example.com', 'not a target'],
        },
      })
    )
    expect(req.asset_group_ids).toEqual(['g1', 'g2'])
    expect(req.asset_group_id).toBe('g1')
    // The API names the assets (an asset without a known name is still sent).
    expect(req.asset_ids).toEqual(['a1', 'a2'])
    // Typed lines: valid ones, normalized, once each.
    expect(req.targets).toEqual(['10.0.0.1', 'example.com'])
  })

  it('stops on typed lines that are not targets', () => {
    expect(
      targetsError(
        form({
          targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: ['ok.example.com', 'nope'] },
        })
      )
    ).toMatch(/1 typed line is not a target/)
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

  it('keeps a workflow scan on its workflow', () => {
    const c = config({
      scan_type: 'workflow',
      scanner_name: undefined,
      scan_workflow_id: 'p9',
    } as Partial<ScanConfig>)
    const f = scanConfigToFormData(c)
    expect(f.mode).toBe('workflow')
    const req = formDataToUpdateRequest(f, c, { canSetZone: false })
    expect(req.scan_workflow_id).toBe('p9')
    expect(req.scanner_name).toBeUndefined()
  })
})

describe('Edit: a cron or RRULE schedule the wizard cannot show', () => {
  const cron = () =>
    config({
      schedule_type: 'crontab',
      schedule_cron: '0 4 * * 1-5',
      schedule_day: undefined,
      schedule_time: undefined,
      schedule_timezone: 'UTC',
    } as Partial<ScanConfig>)
  const rrule = () =>
    config({
      schedule_type: 'rrule',
      schedule_rrule: 'FREQ=WEEKLY;BYDAY=MO,TH;BYHOUR=5',
      schedule_day: undefined,
      schedule_time: undefined,
    } as Partial<ScanConfig>)

  it('saving another change leaves the stored schedule out (unchanged)', () => {
    // It used to be sent as "weekly" without a day: the API refused every
    // edit of such a scan, a rename included.
    for (const c of [cron(), rrule()]) {
      const f = { ...scanConfigToFormData(c), name: 'Renamed' }
      expect(scheduleError(f)).toBeNull()
      const req = formDataToUpdateRequest(f, c, { canSetZone: false })
      expect(req.name).toBe('Renamed')
      for (const key of [
        'schedule_type',
        'schedule_day',
        'schedule_time',
        'schedule_cron',
        'schedule_rrule',
        'run_at',
        'timezone',
      ]) {
        expect(key in req).toBe(false)
      }
    }
  })

  it('shows the stored expression', () => {
    expect(scanConfigToFormData(cron()).schedule.custom).toEqual({
      type: 'crontab',
      expression: '0 4 * * 1-5',
    })
    expect(scanConfigToFormData(rrule()).schedule.custom?.type).toBe('rrule')
  })

  it('replacing it sends the chosen frequency', () => {
    const c = cron()
    const f = scanConfigToFormData(c)
    const replaced = {
      ...f,
      schedule: { ...f.schedule, custom: undefined, frequency: 'weekly' as const, dayOfWeek: 2 },
    }
    const req = formDataToUpdateRequest(replaced, c, { canSetZone: false })
    expect(req.schedule_type).toBe('weekly')
    expect(req.schedule_day).toBe(2)
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

describe('direct target limit', () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => `h${i}.example.com`)

  it('needs a target, and refuses more than the API takes instead of cutting silently', () => {
    expect(
      targetsError(form({ targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: [] } }))
    ).toMatch(/at least one/)
    const at = form({
      targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: many(MAX_DIRECT_TARGETS) },
    })
    expect(targetsError(at)).toBeNull()
    const over = form({
      targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: many(MAX_DIRECT_TARGETS + 5) },
    })
    expect(targetsError(over)).toMatch(/at most 1,000 direct targets; 1,005 are selected/)
    // The request carries every target; the API refuses over the limit.
    expect(formDataToCreateRequest(over).targets).toHaveLength(MAX_DIRECT_TARGETS + 5)
  })

  it('counts picked assets and typed targets once each', () => {
    const f = form({
      targets: {
        ...DEFAULT_NEW_SCAN.targets,
        assetIds: ['a1'],
        assetNames: { a1: 'Example.com' },
        customTargets: ['example.com', 'api.example.com'],
      },
    })
    expect(directTargets(f)).toEqual(['example.com', 'api.example.com'])
  })

  it('an asset group alone is enough', () => {
    expect(
      targetsError(
        form({ targets: { ...DEFAULT_NEW_SCAN.targets, assetGroupIds: ['g1'], customTargets: [] } })
      )
    ).toBeNull()
  })
})

describe('dynamic targets (RFC-068)', () => {
  it('stores *.domain for "host and its subdomains", never a frozen list of names', () => {
    const req = formDataToCreateRequest(
      form({
        targets: {
          ...DEFAULT_NEW_SCAN.targets,
          customTargets: ['example.com', '203.0.113.7'],
          coverage: 'subdomains',
          expandedTargets: ['stale-list.example.com'],
        },
      })
    )
    expect(req.targets).toEqual(['*.example.com', '203.0.113.7'])
  })

  it('adds the wildcard of a picked domain asset, and the recorded addresses for subdomains_ips', () => {
    const req = formDataToCreateRequest(
      form({
        targets: {
          ...DEFAULT_NEW_SCAN.targets,
          customTargets: [],
          assetIds: ['a1'],
          assetNames: { a1: 'shop.example.org' },
          coverage: 'subdomains_ips',
          expandedTargets: ['198.51.100.4'],
        },
      })
    )
    expect(req.asset_ids).toEqual(['a1'])
    expect(req.targets).toEqual(['*.shop.example.org', '198.51.100.4'])
  })

  it('sends target options only when they differ from the defaults', () => {
    expect(formDataToCreateRequest(form()).target_options).toBeUndefined()
    const req = formDataToCreateRequest(
      form({
        targets: {
          ...DEFAULT_NEW_SCAN.targets,
          customTargets: ['203.0.113.0/24'],
          targetOptions: { cidr_mode: 'inventory', seen_within_days: 30 },
        },
      })
    )
    expect(req.target_options).toEqual({ cidr_mode: 'inventory', seen_within_days: 30 })
  })

  it('edit loads the options and sends them whole ({} resets)', () => {
    const loaded = scanConfigToFormData(config({ target_options: { include_stale: true } }))
    expect(loaded.targets.targetOptions).toEqual({ include_stale: true })
    expect(formDataToUpdateRequest(loaded, config(), { canSetZone: false }).target_options).toEqual(
      {
        include_stale: true,
      }
    )
    const cleared = { ...loaded, targets: { ...loaded.targets, targetOptions: {} } }
    expect(
      formDataToUpdateRequest(cleared, config(), { canSetZone: false }).target_options
    ).toEqual({})
  })

  it('counts a wildcard as one direct target', () => {
    expect(
      directTargets(
        form({
          targets: {
            ...DEFAULT_NEW_SCAN.targets,
            customTargets: ['a.io', 'b.io'],
            coverage: 'subdomains',
          },
        })
      )
    ).toEqual(['*.a.io', '*.b.io'])
  })
})

describe('scan intensity (RFC-071)', () => {
  it('sends the chosen intensity on create and on edit, default active', () => {
    expect(formDataToCreateRequest(form()).intensity).toBe('active')
    expect(formDataToCreateRequest(form({ intensity: 'passive' })).intensity).toBe('passive')
    const edited = scanConfigToFormData({ ...config(), intensity: 'intrusive' })
    expect(edited.intensity).toBe('intrusive')
    expect(formDataToUpdateRequest(edited, config(), { canSetZone: false }).intensity).toBe(
      'intrusive'
    )
  })
})

describe('Edit: targets and asset groups', () => {
  const edit = (patch: Partial<NewScanFormData['targets']>) => {
    const c = config()
    const f = scanConfigToFormData(c)
    return formDataToUpdateRequest({ ...f, targets: { ...f.targets, ...patch } }, c, {
      canSetZone: false,
    })
  }

  it('an unchanged edit sends neither (the API keeps them)', () => {
    const req = edit({})
    expect('targets' in req).toBe(false)
    expect('asset_ids' in req).toBe(false)
    expect('asset_group_ids' in req).toBe(false)
  })

  it('order and case alone are not a change', () => {
    expect('targets' in edit({ customTargets: ['EXAMPLE.com'] })).toBe(false)
  })

  it('changed targets are sent whole', () => {
    // They used to be dropped: the save said "updated" and nothing changed.
    expect(edit({ customTargets: ['example.com', 'api.example.com'] }).targets).toEqual([
      'example.com',
      'api.example.com',
    ])
    expect(edit({ customTargets: [] }).targets).toEqual([])
  })

  it('picked assets go by id with the typed targets', () => {
    const req = edit({ assetIds: ['a1'], assetNames: { a1: 'shop.example.com' } })
    expect(req.asset_ids).toEqual(['a1'])
    expect(req.targets).toEqual(['example.com'])
  })

  it('changed asset groups are sent whole', () => {
    expect(edit({ assetGroupIds: ['g1', 'g2'] }).asset_group_ids).toEqual(['g1', 'g2'])
    expect(edit({ assetGroupIds: [] }).asset_group_ids).toEqual([])
  })
})

describe('rule sources', () => {
  const nuclei = (over: Partial<NewScanFormData> = {}) =>
    form({ scannerName: 'nuclei', ruleSources: '', customTemplateIds: [], ...over })

  it('create: omits rule_sources when inheriting and sends each choice otherwise', () => {
    expect(formDataToCreateRequest(nuclei())).not.toHaveProperty('rule_sources')
    for (const choice of ['both', 'platform', 'tenant'] as const) {
      expect(
        formDataToCreateRequest(nuclei({ ruleSources: choice, customTemplateIds: ['t1'] }))
          .rule_sources
      ).toBe(choice)
    }
  })

  it('create: sends custom_template_ids unless the choice is platform', () => {
    const ids = ['t1', 't2']
    expect(
      formDataToCreateRequest(nuclei({ ruleSources: 'tenant', customTemplateIds: ids }))
        .scanner_config
    ).toEqual({ custom_template_ids: ids })
    expect(
      formDataToCreateRequest(nuclei({ ruleSources: 'both', customTemplateIds: ids }))
        .scanner_config
    ).toEqual({ custom_template_ids: ids })
    expect(
      formDataToCreateRequest(nuclei({ ruleSources: 'platform', customTemplateIds: ids }))
        .scanner_config
    ).toBeUndefined()
    expect(formDataToCreateRequest(nuclei({ ruleSources: 'both' })).scanner_config).toBeUndefined()
  })

  it('create: a scanner without templates sends neither', () => {
    const req = formDataToCreateRequest(
      form({ scannerName: 'trivy', ruleSources: 'tenant', customTemplateIds: ['t1'] })
    )
    expect(req).not.toHaveProperty('rule_sources')
    expect(req.scanner_config).toBeUndefined()
  })

  it('tenant without a template is an error; other choices and scanners are not', () => {
    expect(optionsError(nuclei({ ruleSources: 'tenant' }))).toMatch(/template/)
    expect(optionsError(nuclei({ ruleSources: 'tenant', customTemplateIds: ['t1'] }))).toBeNull()
    expect(optionsError(nuclei({ ruleSources: 'both' }))).toBeNull()
    expect(optionsError(nuclei({ ruleSources: '' }))).toBeNull()
    expect(optionsError(form({ scannerName: 'trivy', ruleSources: 'tenant' }))).toBeNull()
    expect(
      optionsError(form({ mode: 'workflow', scannerName: '', ruleSources: 'tenant' }))
    ).toBeNull()
  })

  it('edit: reads rule_sources and the stored template ids', () => {
    const data = scanConfigToFormData(
      config({
        scanner_name: 'semgrep',
        rule_sources: 'tenant',
        scanner_config: { custom_template_ids: ['t1', 7, 't2'], severity: 'high' },
      })
    )
    expect(data.ruleSources).toBe('tenant')
    expect(data.customTemplateIds).toEqual(['t1', 't2'])
    expect(scanConfigToFormData(config()).ruleSources).toBe('')
    expect(scanConfigToFormData(config()).customTemplateIds).toEqual([])
  })

  it('edit: round trips, clears ids and sends "" to inherit', () => {
    const stored = config({
      scanner_name: 'nuclei',
      rule_sources: 'tenant',
      scanner_config: { custom_template_ids: ['t1'], severity: 'high' },
    })
    const opts = { canSetZone: false }
    const same = formDataToUpdateRequest(scanConfigToFormData(stored), stored, opts)
    expect(same.rule_sources).toBe('tenant')
    expect(same.scanner_config).toEqual({ custom_template_ids: ['t1'], severity: 'high' })

    const cleared = formDataToUpdateRequest(
      { ...scanConfigToFormData(stored), ruleSources: '', customTemplateIds: [] },
      stored,
      opts
    )
    expect(cleared.rule_sources).toBe('')
    expect(cleared.scanner_config).toEqual({ severity: 'high' })

    const changed = formDataToUpdateRequest(
      { ...scanConfigToFormData(stored), ruleSources: 'both', customTemplateIds: ['t2', 't3'] },
      stored,
      opts
    )
    expect(changed.rule_sources).toBe('both')
    expect(changed.scanner_config).toEqual({ custom_template_ids: ['t2', 't3'], severity: 'high' })
    // the stored config is not mutated
    expect(stored.scanner_config).toEqual({ custom_template_ids: ['t1'], severity: 'high' })
  })

  it('edit: a scanner without templates keeps scanner_config as stored', () => {
    const stored = config({ scanner_config: { custom_template_ids: ['x'], severity: 'high' } })
    const req = formDataToUpdateRequest(scanConfigToFormData(stored), stored, { canSetZone: false })
    expect(req.scanner_config).toEqual({ custom_template_ids: ['x'], severity: 'high' })
  })

  it('a Tenable.sc scan is unaffected', () => {
    const cfg = { integration_id: 'i1', policy_id: 7, repository_id: 5 }
    const req = formDataToCreateRequest(
      form({ scannerName: 'tenable_sc', scannerConfig: cfg, ruleSources: 'tenant' })
    )
    expect(req).not.toHaveProperty('rule_sources')
    expect(req.scanner_config).not.toHaveProperty('custom_template_ids')
  })
})
