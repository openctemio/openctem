import { describe, it, expect } from 'vitest'
import {
  PRIORITY_CHART_COLORS,
  PRIORITY_ORDER,
  coverageState,
  openCountState,
  STATE_STRIPE,
  STATE_TEXT,
} from '../ctem-colors'
import { SEVERITY_CHART_COLORS } from '@/lib/severity-colors'

describe('ctem-colors', () => {
  it('takes priority colours from the priority tokens, never the severity ones', () => {
    for (const pc of PRIORITY_ORDER) {
      expect(PRIORITY_CHART_COLORS[pc]).toMatch(/^var\(--prio-\d\)$/)
      expect(Object.values(SEVERITY_CHART_COLORS)).not.toContain(PRIORITY_CHART_COLORS[pc])
    }
  })

  it('orders priorities P0..P3', () => {
    expect(PRIORITY_ORDER).toEqual(['P0', 'P1', 'P2', 'P3'])
  })

  it('grades coverage: higher is better', () => {
    expect(coverageState(95)).toBe('good')
    expect(coverageState(80)).toBe('good')
    expect(coverageState(50)).toBe('warn')
    expect(coverageState(0)).toBe('crit')
  })

  it('grades open counts: lower is better, 0 is good', () => {
    expect(openCountState(0)).toBe('good')
    expect(openCountState(2)).toBe('warn')
    expect(openCountState(12)).toBe('crit')
  })

  it('exposes a class token for every health state', () => {
    for (const state of ['good', 'warn', 'crit'] as const) {
      expect(STATE_STRIPE[state]).toBeTruthy()
      expect(STATE_TEXT[state]).toBeTruthy()
    }
  })
})
