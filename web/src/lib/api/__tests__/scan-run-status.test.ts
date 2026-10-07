import { describe, it, expect } from 'vitest'

import {
  SCAN_RUN_STATUSES,
  SCAN_RUN_STATUS_LABELS,
  STEP_RUN_STATUSES,
} from '../scan-workflow-types'
import { RUN_STATUS_FILTERS } from '@/features/scans/components/scan-runs-tab'

// Run and step statuses are spelled as the API stores them
// (pkg/domain/workflow: RunStatusCanceled = "canceled"). The web used to spell
// it "cancelled", so a typed comparison with a canceled run could never match.
describe('workflow run statuses', () => {
  it('use the API spelling of canceled', () => {
    expect(SCAN_RUN_STATUSES).toContain('canceled')
    expect(STEP_RUN_STATUSES).toContain('canceled')
    expect(SCAN_RUN_STATUSES as readonly string[]).not.toContain('cancelled')
    expect(STEP_RUN_STATUSES as readonly string[]).not.toContain('cancelled')
  })

  it('match the API run statuses exactly', () => {
    expect([...SCAN_RUN_STATUSES].sort()).toEqual(
      [
        'pending',
        'running',
        'completed',
        'partial',
        'failed',
        'canceled',
        'timeout',
        // workflow.RunStatusBlocked: a trigger refused before dispatch.
        'blocked',
      ].sort()
    )
  })

  it('label every status', () => {
    for (const s of SCAN_RUN_STATUSES) expect(SCAN_RUN_STATUS_LABELS[s]).toBeTruthy()
  })

  it('offer only real statuses in the Runs filter', () => {
    for (const f of RUN_STATUS_FILTERS) {
      if (f.value === 'all') continue
      expect(SCAN_RUN_STATUSES as readonly string[]).toContain(f.value)
    }
  })
})
