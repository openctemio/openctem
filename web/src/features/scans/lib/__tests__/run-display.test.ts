import { describe, expect, it } from 'vitest'
import { runHref, runKindLabel, runSubjectFindingId } from '../run-display'

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
