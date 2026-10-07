import { describe, expect, it } from 'vitest'

import type { ToolAvailabilityItem } from '@/lib/api/tool-types'
import {
  availabilityByName,
  isRunnable,
  onAnySensor,
  sensorToolExclusions,
  sensorsLabel,
  toolUnavailableReason,
  versionsLabel,
} from '../availability'

function availItem(over: Partial<ToolAvailabilityItem>): ToolAvailabilityItem {
  return {
    name: 'nuclei',
    tool: null,
    in_catalog: true,
    enabled: true,
    status: 'ready',
    sensors_online: 1,
    sensors_total: 1,
    sensors_excluded: 0,
    sensors: [],
    versions: [],
    update_available: false,
    content: [],
    ...over,
  }
}

describe('tool availability helpers', () => {
  it('ready and outdated are runnable; the rest are not', () => {
    expect(isRunnable(availItem({ status: 'ready' }))).toBe(true)
    expect(isRunnable(availItem({ status: 'outdated' }))).toBe(true)
    for (const status of ['no_sensor', 'offline_only', 'disabled'] as const) {
      expect(isRunnable(availItem({ status }))).toBe(false)
    }
  })

  it('explains why a tool cannot run, and says nothing when it can', () => {
    expect(toolUnavailableReason(availItem({ status: 'ready' }))).toBeNull()
    expect(toolUnavailableReason(undefined)).toBeNull()
    expect(
      toolUnavailableReason(
        availItem({ name: 'checkov', status: 'no_sensor', sensors_total: 0, sensors_online: 0 })
      )
    ).toBe('No sensor has checkov')
    expect(
      toolUnavailableReason(
        availItem({ name: 'semgrep', status: 'offline_only', sensors_total: 2, sensors_online: 0 }),
        true
      )
    ).toBe('No online sensor in this zone has semgrep (2 offline)')
    expect(
      toolUnavailableReason(
        availItem({ name: 'zap', status: 'no_sensor', sensors_total: 0, sensors_excluded: 1 })
      )
    ).toMatch(/grant or local policy/)
    expect(toolUnavailableReason(availItem({ name: 'kics', status: 'disabled' }))).toBe(
      'kics is switched off for this organization'
    )
    expect(
      toolUnavailableReason(availItem({ name: 'mine', status: 'disabled', in_catalog: false }))
    ).toBe('mine is not in the tool catalog')
  })

  it('labels sensors and versions', () => {
    expect(sensorsLabel(availItem({ sensors_online: 2, sensors_total: 3 }))).toBe('2/3 online')
    expect(sensorsLabel(availItem({ sensors_online: 0, sensors_total: 0 }))).toBe('none')
    expect(versionsLabel(availItem({}))).toBe('')
    expect(
      versionsLabel(availItem({ min_reported_version: 'v3.4.2', max_reported_version: 'v3.4.2' }))
    ).toBe('v3.4.2')
    expect(
      versionsLabel(availItem({ min_reported_version: 'v3.3.0', max_reported_version: 'v3.4.2' }))
    ).toBe('v3.3.0 – v3.4.2')
  })

  it('a tool is on a sensor when any sensor reports it, allowed or not', () => {
    expect(onAnySensor(availItem({ sensors_total: 0, sensors_excluded: 0 }))).toBe(false)
    expect(onAnySensor(availItem({ sensors_total: 0, sensors_excluded: 1 }))).toBe(true)
    expect(onAnySensor(availItem({ sensors_total: 1 }))).toBe(true)
  })

  it('indexes by name and lists one sensor exclusions', () => {
    const items = [
      availItem({
        name: 'nuclei',
        sensors: [
          {
            id: 's1',
            name: 'edge',
            state: 'online',
            online: true,
            zones: [],
            excluded: 'grant',
            excluded_detail: 'outside the grant (tools)',
          },
        ],
      }),
      availItem({
        name: 'trivy',
        sensors: [{ id: 's1', name: 'edge', state: 'online', online: true, zones: [] }],
      }),
    ]
    expect(availabilityByName(items).get('trivy')?.name).toBe('trivy')
    const ex = sensorToolExclusions(items, 's1')
    expect([...ex.keys()]).toEqual(['nuclei'])
    expect(ex.get('nuclei')).toEqual({ reason: 'grant', detail: 'outside the grant (tools)' })
    expect(sensorToolExclusions(items, 'other').size).toBe(0)
  })
})
