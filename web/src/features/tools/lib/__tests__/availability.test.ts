import { describe, expect, it } from 'vitest'

import type { ToolAvailabilityItem } from '@/lib/api/tool-types'
import { translate } from '@/lib/i18n'
import { en } from '@/lib/i18n/dictionaries/en'
import { vi } from '@/lib/i18n/dictionaries/vi'
import {
  availabilityByName,
  isRunnable,
  onAnySensor,
  sensorToolExclusions,
  sensorsLabel,
  toolExclusionLabel,
  toolStatusDescription,
  toolStatusLabel,
  toolUnavailableReason,
  versionsLabel,
} from '../availability'

type Vars = Record<string, string | number>
const tEn = (key: string, fallback?: string, vars?: Vars) => translate(en, key, fallback, vars)
const tVi = (key: string, fallback?: string, vars?: Vars) => translate(vi, key, fallback, vars)

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
    expect(toolUnavailableReason(availItem({ status: 'ready' }), tEn)).toBeNull()
    expect(toolUnavailableReason(undefined, tEn)).toBeNull()
    expect(
      toolUnavailableReason(
        availItem({ name: 'checkov', status: 'no_sensor', sensors_total: 0, sensors_online: 0 }),
        tEn
      )
    ).toBe('No sensor has checkov')
    expect(
      toolUnavailableReason(
        availItem({ name: 'semgrep', status: 'offline_only', sensors_total: 2, sensors_online: 0 }),
        tEn,
        true
      )
    ).toBe('No online sensor in this zone has semgrep (2 offline)')
    expect(
      toolUnavailableReason(
        availItem({ name: 'zap', status: 'no_sensor', sensors_total: 0, sensors_excluded: 1 }),
        tEn
      )
    ).toMatch(/grant or local policy/)
    expect(toolUnavailableReason(availItem({ name: 'kics', status: 'disabled' }), tEn)).toBe(
      'kics is switched off for this organization'
    )
    expect(
      toolUnavailableReason(availItem({ name: 'mine', status: 'disabled', in_catalog: false }), tEn)
    ).toBe('mine is not in the tool catalog')
  })

  it('gives every reason in Vietnamese, with the tool name and count filled in', () => {
    const cases: [Partial<ToolAvailabilityItem>, boolean, string][] = [
      [{ status: 'no_sensor', sensors_total: 0 }, false, 'Không sensor nào có checkov'],
      [
        { status: 'no_sensor', sensors_total: 0 },
        true,
        'Không sensor nào trong vùng này có checkov',
      ],
      [
        { status: 'offline_only', sensors_total: 2, sensors_online: 0 },
        false,
        'Không sensor trực tuyến nào có checkov (2 đang ngoại tuyến)',
      ],
      [
        { status: 'offline_only', sensors_total: 2, sensors_online: 0 },
        true,
        'Không sensor trực tuyến nào trong vùng này có checkov (2 đang ngoại tuyến)',
      ],
      [
        { status: 'no_sensor', sensors_total: 0, sensors_excluded: 1 },
        false,
        'Không sensor nào được phép chạy checkov: quyền hạn hoặc chính sách cục bộ của sensor không cho phép',
      ],
      [
        { status: 'no_sensor', sensors_total: 0, sensors_excluded: 1 },
        true,
        'Không sensor nào trong vùng này được phép chạy checkov: quyền hạn hoặc chính sách cục bộ của sensor không cho phép',
      ],
      [{ status: 'disabled' }, false, 'checkov đã bị tắt cho tổ chức này'],
      [{ status: 'disabled', in_catalog: false }, false, 'checkov không có trong danh mục công cụ'],
    ]
    for (const [over, inZone, want] of cases) {
      const item = availItem({ name: 'checkov', ...over })
      expect(toolUnavailableReason(item, tVi, inZone)).toBe(want)
      // Every branch has its own key: the English text never shows in Vietnamese.
      expect(toolUnavailableReason(item, tVi, inZone)).not.toBe(
        toolUnavailableReason(item, tEn, inZone)
      )
    }
  })

  it('labels sensors and versions', () => {
    expect(sensorsLabel(availItem({ sensors_online: 2, sensors_total: 3 }))).toBe('2/3 online')
    expect(sensorsLabel(availItem({ sensors_online: 0, sensors_total: 0 }))).toBe('none')
    expect(sensorsLabel(availItem({ sensors_online: 2, sensors_total: 3 }), tVi)).toBe(
      '2/3 trực tuyến'
    )
    expect(sensorsLabel(availItem({ sensors_online: 0, sensors_total: 0 }), tVi)).toBe('không có')
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

  it('reads statuses and exclusion reasons in Vietnamese', () => {
    for (const status of ['ready', 'outdated', 'offline_only', 'no_sensor', 'disabled'] as const) {
      expect(toolStatusLabel(status, tVi)).not.toBe(toolStatusLabel(status, tEn))
      expect(toolStatusDescription(status, tVi)).not.toBe(toolStatusDescription(status, tEn))
    }
    expect(toolStatusLabel('no_sensor', tVi)).toBe('Không có sensor')
    expect(toolExclusionLabel('grant', tVi)).not.toBe(toolExclusionLabel('grant', tEn))
    expect(toolExclusionLabel('local_policy', tVi)).not.toBe(
      toolExclusionLabel('local_policy', tEn)
    )
  })
})
