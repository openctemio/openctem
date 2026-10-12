import { describe, expect, it } from 'vitest'

import type { Sensor } from '@/lib/api/sensor-types'

import {
  isSensorEditDirty,
  reportedToolNames,
  sensorEditDraft,
  sensorUpdateBody,
  validateSensorEdit,
  zoneChanges,
} from '../sensor-edit'

const base: Pick<Sensor, 'name' | 'description' | 'status' | 'max_concurrent_jobs' | 'reported'> = {
  name: 'dmz-01',
  description: 'DMZ scanner',
  status: 'active',
  max_concurrent_jobs: 5,
  reported: {
    tools: [
      { name: 'trivy', version: '0.58', installed: true },
      { name: 'nuclei', version: '3.3', installed: true },
      { name: 'semgrep', installed: false },
    ],
    capabilities: ['dast', 'sca'],
    max_concurrent_jobs: 4,
    reported_at: '2026-10-01T00:00:00Z',
  },
}

describe('reportedToolNames', () => {
  it('lists the installed tools, sorted', () => {
    expect(reportedToolNames(base)).toEqual(['nuclei', 'trivy'])
  })
  it('is null before the first report', () => {
    expect(reportedToolNames({ reported: null })).toBeNull()
    expect(reportedToolNames({ reported: { ...base.reported!, tools: null } })).toBeNull()
  })
})

describe('sensorEditDraft', () => {
  it('starts from the sensor', () => {
    expect(sensorEditDraft(base)).toEqual({
      name: 'dmz-01',
      description: 'DMZ scanner',
      enabled: true,
      maxJobs: '5',
      zoneIds: [],
    })
  })
  it('a disabled sensor starts not enabled', () => {
    expect(sensorEditDraft({ ...base, status: 'disabled' }).enabled).toBe(false)
  })
})

describe('sensorUpdateBody', () => {
  const initial = sensorEditDraft(base)

  it('sends nothing for an untouched form', () => {
    expect(sensorUpdateBody(initial, initial)).toEqual({})
    expect(isSensorEditDirty(initial, initial)).toBe(false)
  })

  it('never sends revoked: the switch maps to active / disabled', () => {
    expect(sensorUpdateBody({ ...initial, enabled: false }, initial)).toEqual({
      status: 'disabled',
    })
    const dis = sensorEditDraft({ ...base, status: 'disabled' })
    expect(sensorUpdateBody({ ...dis, enabled: true }, dis)).toEqual({ status: 'active' })
  })

  it('never sends tools: the sensor reports them and the grant narrows them', () => {
    const body = sensorUpdateBody({ ...initial, name: 'x', maxJobs: '2' }, initial)
    expect(body).not.toHaveProperty('tools')
    expect(body).not.toHaveProperty('capabilities')
  })

  it('sends name, description and the job limit only when changed', () => {
    const body = sensorUpdateBody({ ...initial, name: '  dmz-02 ', maxJobs: '3' }, initial)
    expect(body).toEqual({ name: 'dmz-02', max_concurrent_jobs: 3 })
  })
})

describe('validateSensorEdit', () => {
  const initial = sensorEditDraft(base)
  it('requires a name', () => {
    expect(validateSensorEdit({ ...initial, name: ' ' }, initial).name).toBeTruthy()
  })
  it('bounds the job limit to 1..100', () => {
    for (const v of ['0', '101', '2.5', '', 'x']) {
      expect(validateSensorEdit({ ...initial, maxJobs: v }, initial).maxJobs).toBeTruthy()
    }
    expect(validateSensorEdit({ ...initial, maxJobs: '100' }, initial).maxJobs).toBeUndefined()
  })
})

describe('zoneChanges', () => {
  it('splits joins and leaves', () => {
    const initial = sensorEditDraft(base, ['a', 'b'])
    expect(zoneChanges({ ...initial, zoneIds: ['b', 'c'] }, initial)).toEqual({
      join: ['c'],
      leave: ['a'],
    })
  })
})
