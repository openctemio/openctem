import { describe, expect, it } from 'vitest'
import {
  policyTriggerLabel,
  runHref,
  runKindLabel,
  runSubjectFindingId,
  runTargetNote,
  runTriggeredByLabel,
} from '../run-display'

describe('run kinds', () => {
  it('names each kind; a run from before kinds is a scan', () => {
    expect(runKindLabel(undefined)).toBe('Scan')
    expect(runKindLabel('retest')).toBe('Retest')
    expect(runKindLabel('quick')).toBe('Quick scan')
    expect(runKindLabel('unknown-kind')).toBe('Run')
  })

  it('reads the finding a run is about', () => {
    expect(runSubjectFindingId({ subject: { finding_id: 'f-1' } })).toBe('f-1')
    expect(runSubjectFindingId({ subject: { finding_id: 7 } })).toBeNull()
    expect(runSubjectFindingId({})).toBeNull()
  })

  it('links one run on the Runs page, encoded', () => {
    expect(runHref('a b')).toBe('/scans/runs?run=a%20b')
  })
})

describe('policy runs', () => {
  it('a platform policy that started a run is named, never "System"', () => {
    expect(runTriggeredByLabel({ trigger: { type: 'policy', id: 'coverage' } })).toBe(
      'Automatic coverage'
    )
    expect(runTriggeredByLabel({ trigger: { type: 'policy', id: 'enrichment' } })).toBe(
      'Automatic enrichment'
    )
    expect(runTriggeredByLabel({ trigger: { type: 'policy' } })).toBe('Automatic')
    expect(policyTriggerLabel('something-new')).toBe('Automatic')
  })
})

describe('runTargetNote', () => {
  it('says how many targets did not answer or were skipped, and nothing otherwise', () => {
    expect(runTargetNote({})).toBeNull()
    expect(runTargetNote({ unreachable_target_count: 0, skipped_target_count: 0 })).toBeNull()
    expect(runTargetNote({ unreachable_target_count: 3 })).toBe('3 unreachable')
    expect(runTargetNote({ skipped_target_count: 2 })).toBe('2 skipped')
    expect(runTargetNote({ unreachable_target_count: 3, skipped_target_count: 2 })).toBe(
      '3 unreachable · 2 skipped'
    )
  })
})
