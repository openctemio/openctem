/**
 * The monitoring states are declared in the API (pkg/domain/asset): the web
 * lists the same values, in the same precedence order, each with an en and a
 * vi label, and the inventory URL round-trips the filter.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en/assets.json'
import vi from '@/lib/i18n/dictionaries/vi/assets.json'
import { MONITORING_STATES } from '../monitoring-state'
import { parseInventoryFilters, serializeInventoryFilters } from '../inventory-url'

function apiStates(): string[] {
  const src = readFileSync(
    resolve(__dirname, '../../../../../../api/pkg/domain/asset/monitoring_state.go'),
    'utf8'
  )
  const consts = new Map(
    [...src.matchAll(/(Monitoring[A-Za-z]+)\s+MonitoringState = "([a-z_]+)"/g)].map((m) => [
      m[1],
      m[2],
    ])
  )
  const list = src.slice(src.indexOf('func MonitoringStates()'))
  const body = list.slice(list.indexOf('{'), list.indexOf('}\n}'))
  return [...body.matchAll(/(Monitoring[A-Za-z]+)/g)]
    .map((m) => consts.get(m[1]))
    .filter((v): v is string => !!v)
}

describe('monitoring states', () => {
  it('matches the API set', () => {
    expect([...MONITORING_STATES].sort()).toEqual(apiStates().sort())
  })

  it('has en and vi labels', () => {
    for (const s of MONITORING_STATES) {
      expect((en as Record<string, string>)[`assets.monitoring.state.${s}`], s).toBeTruthy()
      expect((vi as Record<string, string>)[`assets.monitoring.state.${s}`], s).toBeTruthy()
    }
  })

  it('round-trips the inventory filter', () => {
    const f = parseInventoryFilters(
      new URLSearchParams('monitoring_state=pending_decision,unvalidated')
    )
    expect(f.monitoringState).toEqual(['pending_decision', 'unvalidated'])
    expect(serializeInventoryFilters(f).get('monitoring_state')).toBe(
      'pending_decision,unvalidated'
    )
  })
})
