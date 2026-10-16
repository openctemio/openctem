/**
 * Finding status registry tests: one status set for every source, labels in
 * en and vi with no duplicates, categories for the filter.
 */

import { describe, it, expect } from 'vitest'
import * as types from '../finding.types'
import {
  ALL_FINDING_STATUSES,
  FINDING_STATUS_CONFIG,
  findingStatusesInCategory,
  isFindingStatus,
} from '../finding.types'
import type { FindingStatus } from '../finding.types'
import { en, vi } from '@/lib/i18n/dictionaries'

// The Go list (vulnerability.AllFindingStatuses) and the DB CHECK
// (migration 001378). Change all three together.
const CANONICAL: FindingStatus[] = [
  'new',
  'confirmed',
  'in_progress',
  'fix_applied',
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

describe('the lifecycle rules live on the server', () => {
  it('the console keeps no copy of the transition map', () => {
    for (const name of [
      'STATUS_TRANSITIONS',
      'AUTOMATED_STATUSES',
      'PENTEST_STATUSES',
      'getStatusesForSource',
    ]) {
      expect(name in types, name).toBe(false)
    }
  })
})

describe('retired statuses', () => {
  it('validated_fixed and not_observed are fields now, not statuses', () => {
    expect(Object.keys(FINDING_STATUS_CONFIG)).not.toContain('validated_fixed')
    expect(Object.keys(FINDING_STATUS_CONFIG)).not.toContain('not_observed')
  })
})
