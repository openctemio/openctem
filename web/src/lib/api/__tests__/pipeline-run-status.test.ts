import { describe, it, expect } from 'vitest'

import {
  PIPELINE_RUN_STATUSES,
  PIPELINE_RUN_STATUS_LABELS,
  STEP_RUN_STATUSES,
} from '../pipeline-types'
import { RUN_STATUS_FILTERS } from '@/features/scans/components/scan-runs-tab'

// Run and step statuses are spelled as the API stores them
// (pkg/domain/pipeline: RunStatusCanceled = "canceled"). The web used to spell
// it "cancelled", so a typed comparison with a canceled run could never match.
describe('pipeline run statuses', () => {
  it('use the API spelling of canceled', () => {
    expect(PIPELINE_RUN_STATUSES).toContain('canceled')
    expect(STEP_RUN_STATUSES).toContain('canceled')
    expect(PIPELINE_RUN_STATUSES as readonly string[]).not.toContain('cancelled')
    expect(STEP_RUN_STATUSES as readonly string[]).not.toContain('cancelled')
  })

  it('match the API run statuses exactly', () => {
    expect([...PIPELINE_RUN_STATUSES].sort()).toEqual(
      [
        'pending',
        'running',
        'completed',
        'partial',
        'failed',
        'canceled',
        'timeout',
        // pipeline.RunStatusBlocked: a trigger refused before dispatch.
        'blocked',
      ].sort()
    )
  })

  it('label every status', () => {
    for (const s of PIPELINE_RUN_STATUSES) expect(PIPELINE_RUN_STATUS_LABELS[s]).toBeTruthy()
  })

  it('offer only real statuses in the Runs filter', () => {
    for (const f of RUN_STATUS_FILTERS) {
      if (f.value === 'all') continue
      expect(PIPELINE_RUN_STATUSES as readonly string[]).toContain(f.value)
    }
  })
})
