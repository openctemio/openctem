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
      '3 unreachable, 2 skipped'
    )
    // Names that no longer resolve are worded as such, apart from other skips.
    expect(runTargetNote({ skipped_target_count: 157, no_longer_resolve_count: 157 })).toBe(
      '157 names no longer resolve'
    )
    expect(runTargetNote({ skipped_target_count: 5, no_longer_resolve_count: 3 })).toBe(
      '2 skipped, 3 names no longer resolve'
    )
  })
})

describe('continuous coverage runs', () => {
  it('maps each kind filter to the list query', async () => {
    const { runKindQuery } = await import('../run-display')
    expect(runKindQuery('all')).toEqual({})
    expect(runKindQuery('scan')).toEqual({ kind: 'scan' })
    expect(runKindQuery('retest')).toEqual({ kind: 'retest' })
  })

  it('maps each origin filter to the list query, people by default', async () => {
    const { runOriginQuery, DEFAULT_RUN_ORIGIN } = await import('../run-display')
    expect(DEFAULT_RUN_ORIGIN).toBe('user')
    expect(runOriginQuery('user')).toEqual({ origin: 'user' })
    expect(runOriginQuery('system')).toEqual({ origin: 'system' })
    // All: no origin, so system runs stay reachable.
    expect(runOriginQuery('all')).toEqual({})
    expect(runOriginQuery('bogus')).toEqual({})
  })

  it('words the platform policy that owns the scan', async () => {
    const { runManagedLabel } = await import('../run-display')
    expect(runManagedLabel('coverage')).toBe('Continuous coverage')
    expect(runManagedLabel('enrichment')).toBe('Automatic enrichment')
    expect(runManagedLabel('web_verify')).toBe('Managed by the platform')
    expect(runManagedLabel(undefined)).toBeNull()
  })
})
