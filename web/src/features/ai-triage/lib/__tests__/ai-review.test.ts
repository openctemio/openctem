import { describe, it, expect } from 'vitest'

import type { AIRun } from '../../api/use-ai-agents'
import { aiReviewOf, codeWords } from '../ai-review'

const run = (over: Partial<AIRun>): AIRun => ({
  id: 'r',
  kind: 'triage.v1',
  executor: 'tenant_worker',
  status: 'completed',
  trigger: 'schedule',
  accountable: [],
  created_at: '2026-11-25T00:00:00Z',
  ...over,
})

describe('aiReviewOf', () => {
  it('is null without a run', () => {
    expect(aiReviewOf([])).toBeNull()
    expect(aiReviewOf(undefined)).toBeNull()
  })
  it('reads the latest run only', () => {
    expect(aiReviewOf([run({ status: 'queued' }), run({ outcome: 'applied' })])?.state).toBe(
      'waiting'
    )
  })
  it('maps live runs', () => {
    expect(aiReviewOf([run({ status: 'running' })])?.state).toBe('reviewing')
  })
  it('maps outcomes', () => {
    expect(aiReviewOf([run({ outcome: 'applied' })])?.state).toBe('changed')
    expect(aiReviewOf([run({ outcome: 'proposed' })])?.state).toBe('decide')
    expect(aiReviewOf([run({ outcome: 'no_change' })])?.state).toBe('agrees')
    expect(aiReviewOf([run({ outcome: 'abstained' })])?.state).toBe('unsure')
  })
  it('names why a run ended without a review', () => {
    const r = aiReviewOf([run({ status: 'failed', error_code: 'deadline_exceeded' })])
    expect(r?.state).toBe('not_reviewed')
    expect(r?.reason).toBe('deadline_exceeded')
  })
  it('turns a code into words', () => {
    expect(codeWords('finding_changed')).toBe('finding changed')
  })
})
