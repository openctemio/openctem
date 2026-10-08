/**
 * Finding status registry tests: one status set for every source, labels in
 * en and vi with no duplicates, categories for the filter, transitions.
 */

import { describe, it, expect } from 'vitest'
import {
  getStatusesForSource,
  PENTEST_STATUSES,
  AUTOMATED_STATUSES,
  ALL_FINDING_STATUSES,
  STATUS_TRANSITIONS,
  FINDING_STATUS_CONFIG,
  findingStatusesInCategory,
  isFindingStatus,
} from '../finding.types'
import type { FindingStatus } from '../finding.types'
import en from '@/lib/i18n/dictionaries/en.json'
import vi from '@/lib/i18n/dictionaries/vi.json'

// The Go list (vulnerability.AllFindingStatuses) and the DB CHECK
// (migration 001378). Change all three together.
const CANONICAL: FindingStatus[] = [
  'new',
  'confirmed',
  'in_progress',
  'fix_applied',
  'validated_fixed',
  'not_observed',
  'resolved',
  'false_positive',
  'accepted',
  'duplicate',
  'draft',
  'in_review',
]

describe('the finding status registry', () => {
  it('holds exactly the canonical statuses', () => {
    expect([...ALL_FINDING_STATUSES].sort()).toEqual([...CANONICAL].sort())
  })

  it('has no retired alias', () => {
    for (const alias of ['remediation', 'retest', 'verified', 'accepted_risk', 'open', 'triaged']) {
      expect(isFindingStatus(alias), alias).toBe(false)
    }
  })

  it('has one label per status, no two statuses sharing a label', () => {
    const labels = ALL_FINDING_STATUSES.map((s) => FINDING_STATUS_CONFIG[s].label)
    expect(new Set(labels).size).toBe(labels.length)
  })

  it('has an en and a vi label for every status, distinct within each language', () => {
    for (const dict of [en, vi] as Record<string, string>[]) {
      const labels = ALL_FINDING_STATUSES.map((s) => dict[FINDING_STATUS_CONFIG[s].labelKey])
      for (const [i, l] of labels.entries()) {
        expect(l, `missing ${FINDING_STATUS_CONFIG[ALL_FINDING_STATUSES[i]].labelKey}`).toBeTruthy()
      }
      expect(new Set(labels).size).toBe(labels.length)
    }
  })

  it('groups every status into exactly one filter category', () => {
    const grouped = (['open', 'in_progress', 'closed'] as const).flatMap(findingStatusesInCategory)
    expect([...grouped].sort()).toEqual([...CANONICAL].sort())
    expect(findingStatusesInCategory('closed').sort()).toEqual(
      ['accepted', 'duplicate', 'false_positive', 'resolved'].sort()
    )
  })
})

describe('statuses per source', () => {
  it('pentest findings use the shared statuses plus draft and in_review', () => {
    expect(getStatusesForSource('pentest')).toEqual(PENTEST_STATUSES)
    expect([...PENTEST_STATUSES].sort()).toEqual(
      [
        'draft',
        'in_review',
        'confirmed',
        'in_progress',
        'fix_applied',
        'resolved',
        'false_positive',
        'accepted',
      ].sort()
    )
  })

  it('other sources use the automated statuses', () => {
    for (const source of ['sast', 'dast', 'sca', 'unknown_scanner']) {
      expect(getStatusesForSource(source)).toEqual(AUTOMATED_STATUSES)
    }
    expect(AUTOMATED_STATUSES).not.toContain('draft')
    expect(AUTOMATED_STATUSES).not.toContain('in_review')
  })
})

describe('STATUS_TRANSITIONS', () => {
  it('has an entry for every status and only valid targets', () => {
    for (const status of ALL_FINDING_STATUSES) {
      expect(STATUS_TRANSITIONS[status], status).toBeDefined()
      for (const target of STATUS_TRANSITIONS[status]) {
        expect(isFindingStatus(target), `${status} -> ${target}`).toBe(true)
      }
    }
  })

  it('pentest pre-publication moves', () => {
    expect(STATUS_TRANSITIONS.draft).toContain('in_review')
    expect(STATUS_TRANSITIONS.in_review).toContain('confirmed')
  })
})

describe('not_observed status', () => {
  it('is an open (in progress) status, never closed', () => {
    expect(FINDING_STATUS_CONFIG.not_observed.category).toBe('in_progress')
    expect(FINDING_STATUS_CONFIG.not_observed.label).toBe('Not Observed')
  })

  it('cannot be chosen by a person: no transition leads to it', () => {
    for (const [from, targets] of Object.entries(STATUS_TRANSITIONS)) {
      expect(targets, `${from} offers not_observed`).not.toContain('not_observed' as FindingStatus)
    }
  })

  it('leaves to an open state, a verified close or a disposition', () => {
    expect(STATUS_TRANSITIONS.not_observed).toEqual(
      expect.arrayContaining(['confirmed', 'in_progress', 'resolved'])
    )
  })
})
