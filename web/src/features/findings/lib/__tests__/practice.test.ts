import { describe, it, expect } from 'vitest'
import {
  DEFAULT_PRACTICE_VIEW,
  FINDING_PRACTICES,
  parsePracticeView,
  practiceTabs,
  practiceViewParams,
} from '../practice'

describe('practice view', () => {
  it('opens on vulnerabilities: every practice except compliance', () => {
    expect(DEFAULT_PRACTICE_VIEW).toBe('vulnerabilities')
    expect(parsePracticeView(null)).toBe('vulnerabilities')
    expect(parsePracticeView('')).toBe('vulnerabilities')
    expect(parsePracticeView('nonsense')).toBe('vulnerabilities')
    expect(practiceViewParams('vulnerabilities')).toEqual({ practice_not: 'compliance' })
  })

  it('maps compliance, a single practice and all to API params', () => {
    expect(parsePracticeView('compliance')).toBe('compliance')
    expect(practiceViewParams('compliance')).toEqual({ practice: 'compliance' })
    expect(parsePracticeView('ASPM')).toBe('aspm')
    expect(practiceViewParams('aspm')).toEqual({ practice: 'aspm' })
    expect(parsePracticeView('all')).toBe('all')
    expect(practiceViewParams('all')).toEqual({})
  })

  it('has the nine fixed practices', () => {
    expect(FINDING_PRACTICES).toHaveLength(9)
    expect(FINDING_PRACTICES).toContain('compliance')
  })

  it('shows vulnerabilities, compliance, non-empty practices and all', () => {
    const counts = { aspm: 4, infra: 0, compliance: 2, external: 1 }
    expect(practiceTabs(counts, 'vulnerabilities')).toEqual([
      'vulnerabilities',
      'compliance',
      'aspm',
      'external',
      'all',
    ])
    // The chosen practice stays even when it has no findings.
    expect(practiceTabs(counts, 'infra')).toContain('infra')
    // Before the counts arrive: the three main tabs.
    expect(practiceTabs(undefined, 'vulnerabilities')).toEqual([
      'vulnerabilities',
      'compliance',
      'all',
    ])
  })
})
