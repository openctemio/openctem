import { describe, expect, it } from 'vitest'

import {
  ACTIONABLE_SEVERITIES,
  SEVERITY_LABELS,
  SEVERITY_LEVELS,
  actionableTotal,
  compareSeverity,
  highestSeverity,
  isInformational,
  normalizeSeverity,
  severityCounts,
  severityRank,
} from '@/lib/severity'
import {
  ASSET_CRITICALITY_LEVELS,
  CRITICALITY_LABELS,
  DEFAULT_ASSET_CRITICALITY,
  RATED_CRITICALITY_LEVELS,
  criticalityOptions,
  criticalityRank,
  normalizeCriticality,
} from '@/lib/criticality'
import { SEVERITY_ORDER, severityChartData } from '@/lib/severity-colors'
import { CRITICALITY_BADGE_SOFT, CRITICALITY_CHART_COLORS } from '@/lib/criticality-colors'
import { en, vi } from '@/lib/i18n/dictionaries'

describe('severity scale', () => {
  it('has info, most severe first', () => {
    expect(SEVERITY_LEVELS).toEqual(['critical', 'high', 'medium', 'low', 'info'])
    expect(SEVERITY_ORDER).toEqual([...SEVERITY_LEVELS])
    expect(ACTIONABLE_SEVERITIES).toEqual(['critical', 'high', 'medium', 'low'])
  })

  it('folds none (CVSS 0.0) into info and rejects unknown values', () => {
    expect(normalizeSeverity('none')).toBe('info')
    expect(normalizeSeverity(' INFO ')).toBe('info')
    expect(normalizeSeverity('Critical')).toBe('critical')
    expect(normalizeSeverity('constructor')).toBeUndefined()
    expect(normalizeSeverity(undefined)).toBeUndefined()
    expect(isInformational('none')).toBe(true)
    expect(isInformational('low')).toBe(false)
  })

  it('sorts most severe first and unknowns last', () => {
    expect(['info', 'bogus', 'critical', 'low'].sort(compareSeverity)).toEqual([
      'critical',
      'low',
      'info',
      'bogus',
    ])
    expect(severityRank('info')).toBe(4)
    expect(highestSeverity(['info', 'none'])).toBe('info')
    expect(highestSeverity(['low', 'high', 'info'])).toBe('high')
    expect(highestSeverity([])).toBeUndefined()
  })

  it('reads API count maps with info, folding none, and keeps info out of the actionable total', () => {
    const c = severityCounts({ critical: 1, high: 2, low: 3, info: 4, none: 5, bogus: 9 })
    expect(c).toEqual({ critical: 1, high: 2, medium: 0, low: 3, info: 9 })
    expect(actionableTotal(c)).toBe(6)
    expect(severityCounts(null).info).toBe(0)
  })

  it('charts info as its own Informational slice, in scale order, zeros dropped', () => {
    expect(severityChartData({ info: 2, critical: 1, medium: 0 }).map((r) => r.name)).toEqual([
      'Critical',
      'Informational',
    ])
  })

  it('labels every level in en and vi', () => {
    for (const s of SEVERITY_LEVELS) {
      expect(SEVERITY_LABELS[s]).toBeTruthy()
      expect((en as Record<string, string>)[`severity.${s}`]).toBeTruthy()
      expect((vi as Record<string, string>)[`severity.${s}`]).toBeTruthy()
    }
  })
})

describe('criticality scale', () => {
  it('lets assets be Not rated and keeps groups/units rated', () => {
    expect(ASSET_CRITICALITY_LEVELS).toEqual(['critical', 'high', 'medium', 'low', 'none'])
    expect(RATED_CRITICALITY_LEVELS).toEqual(['critical', 'high', 'medium', 'low'])
    expect(CRITICALITY_LABELS.none).toBe('Not rated')
    // A new asset is medium: unknown is not "unimportant" (none scores 0).
    expect(DEFAULT_ASSET_CRITICALITY).toBe('medium')
  })

  it('has a colour and an en/vi label for every asset level', () => {
    for (const c of ASSET_CRITICALITY_LEVELS) {
      expect(CRITICALITY_BADGE_SOFT[c]).toBeTruthy()
      expect(CRITICALITY_CHART_COLORS[c]).toBeTruthy()
      expect((en as Record<string, string>)[`criticality.${c}`]).toBeTruthy()
      expect((vi as Record<string, string>)[`criticality.${c}`]).toBeTruthy()
    }
  })

  it('normalises and ranks', () => {
    expect(normalizeCriticality('NONE')).toBe('none')
    expect(normalizeCriticality('info')).toBeUndefined()
    expect(normalizeCriticality('toString')).toBeUndefined()
    expect(criticalityRank('none')).toBe(4)
    expect(criticalityRank('bogus')).toBe(5)
  })

  it('builds picker options from a level list', () => {
    expect(criticalityOptions(ASSET_CRITICALITY_LEVELS).map((o) => o.value)).toEqual([
      ...ASSET_CRITICALITY_LEVELS,
    ])
    expect(criticalityOptions(ASSET_CRITICALITY_LEVELS)[4].label).toBe('Not rated')
  })
})
