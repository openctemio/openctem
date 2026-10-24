import { describe, expect, it } from 'vitest'
import {
  isPriorityClass,
  PRIORITY_BOX_CLASS,
  PRIORITY_CHART_COLORS,
  PRIORITY_DOT_CLASS,
  PRIORITY_ORDER,
} from '../priority-colors'
import { seriesVar } from '../chart-palette'
import { SEVERITY_CHART_COLORS } from '../severity-colors'
import { CRITICALITY_BADGE_SOFT } from '../criticality-colors'
import { STATUS_TONES, STATUS_TONE_CLASS } from '../status-colors'
import { FINDING_STATUS_CONFIG } from '@/features/findings/types/finding.types'

describe('priority colours', () => {
  it('has one entry per class, P0 first', () => {
    expect(PRIORITY_ORDER).toEqual(['P0', 'P1', 'P2', 'P3'])
    for (const pc of PRIORITY_ORDER) {
      expect(PRIORITY_BOX_CLASS[pc]).toBeTruthy()
      expect(PRIORITY_DOT_CLASS[pc]).toBeTruthy()
    }
  })

  it('a chart series for P0 is the same colour as the list badge token', () => {
    PRIORITY_ORDER.forEach((pc, i) => {
      expect(seriesVar(pc, i)).toBe(PRIORITY_CHART_COLORS[pc])
      expect(PRIORITY_CHART_COLORS[pc]).toBe(`var(--prio-${i})`)
      expect(PRIORITY_DOT_CLASS[pc]).toBe(`bg-prio-${i}`)
    })
  })

  it('does not reuse a severity colour', () => {
    for (const pc of PRIORITY_ORDER)
      expect(Object.values(SEVERITY_CHART_COLORS)).not.toContain(PRIORITY_CHART_COLORS[pc])
  })

  it('recognises only the four classes', () => {
    expect(isPriorityClass('P2')).toBe(true)
    expect(isPriorityClass('P4')).toBe(false)
    expect(isPriorityClass(undefined)).toBe(false)
  })
})

describe('other scales share the one set of tokens', () => {
  it('criticality critical/high/medium use the severity classes', () => {
    expect(CRITICALITY_BADGE_SOFT.critical).toContain('sev-critical')
    expect(CRITICALITY_BADGE_SOFT.high).toContain('sev-high')
    expect(CRITICALITY_BADGE_SOFT.medium).toContain('sev-medium')
  })

  it('finding statuses take a workflow tone, never a severity or priority class', () => {
    for (const cfg of Object.values(FINDING_STATUS_CONFIG)) {
      expect(STATUS_TONES).toContain(cfg.tone)
      expect(STATUS_TONE_CLASS[cfg.tone]).not.toMatch(
        /red-|orange-|yellow-|amber-|blue-|sev-|prio-|signal/
      )
    }
  })
})
