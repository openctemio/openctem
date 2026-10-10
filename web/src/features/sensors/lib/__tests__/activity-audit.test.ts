import { Undo2, User } from 'lucide-react'
import { describe, expect, it } from 'vitest'

import { en, vi } from '@/lib/i18n/dictionaries'
import type { SensorActivityItem } from '@/lib/api/sensor-types'

import { describeSensorActivity, type Translate } from '../activity'

const t: Translate = (_key, fallback = '', vars) =>
  Object.entries(vars ?? {}).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), fallback)

function auditItem(action: string, extra: Partial<SensorActivityItem> = {}): SensorActivityItem {
  return {
    id: 'a:1',
    at: '2026-10-03T12:00:00Z',
    category: 'people',
    type: 'audit',
    source: 'audit',
    summary: action,
    action,
    actor: 'system',
    result: 'success',
    details: {
      message: "Sensor 'edge-1' revoked: 2 held commands re-queued, 1 failed",
    },
    ...extra,
  }
}

describe('describeSensorActivity: audit rows', () => {
  it('labels sensor.commands_released instead of the raw action', () => {
    const v = describeSensorActivity(auditItem('sensor.commands_released'), t, 'en')
    expect(v.title).toBe('Jobs it held taken back (re-queued or failed)')
    expect(v.title).not.toContain('commands_released')
    expect(v.icon).toBe(Undo2)
    expect(v.details).toEqual([
      'By the system',
      "Sensor 'edge-1' revoked: 2 held commands re-queued, 1 failed",
    ])
  })

  it('uses the translated title when the dictionary has one', () => {
    const tr: Translate = (key, fallback = '') => (vi as Record<string, string>)[key] ?? fallback
    const v = describeSensorActivity(auditItem('sensor.commands_released'), tr, 'vi')
    expect(v.title).toBe((vi as Record<string, string>)['sensors.activity.audit.commands_released'])
  })

  it('falls back to a generic icon for an action without one', () => {
    const v = describeSensorActivity(auditItem('sensor.identity_cloned'), t, 'en')
    expect(v.icon).toBe(User)
  })

  it('has every sensor audit title in every locale', () => {
    const prefix = 'sensors.activity.audit.'
    const enKeys = Object.keys(en).filter((k) => k.startsWith(prefix))
    const viKeys = Object.keys(vi).filter((k) => k.startsWith(prefix))
    expect(enKeys).toContain(`${prefix}commands_released`)
    expect(viKeys.sort()).toEqual(enKeys.sort())
  })
})
