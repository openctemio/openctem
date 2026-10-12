import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockGet = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...args: unknown[]) => mockGet(...args),
}))

import {
  completionWarning,
  completionWarningText,
  fetchLiveCampaignCounts,
  openFindingCount,
  progressPercent,
} from '../campaign-completion'

describe('openFindingCount', () => {
  it('is the findings in scope that are not closed', () => {
    expect(openFindingCount({ finding_count: 4, resolved_count: 0 })).toBe(4)
    expect(openFindingCount({ finding_count: 4, resolved_count: 3 })).toBe(1)
  })

  it('is never negative', () => {
    expect(openFindingCount({ finding_count: 2, resolved_count: 5 })).toBe(0)
  })
})

describe('completionWarning', () => {
  it('warns about a campaign completed with 0 of 4 findings closed (the reported case)', () => {
    const w = completionWarning([{ finding_count: 4, resolved_count: 0 }])
    expect(w).toEqual({ open: 4, total: 4, campaigns: 1 })
    expect(completionWarningText(w!)).toBe('4 of 4 findings are still open.')
  })

  it('does not ask when every finding is closed', () => {
    expect(completionWarning([{ finding_count: 4, resolved_count: 4 }])).toBeNull()
  })

  it('does not ask for a campaign with no findings', () => {
    expect(completionWarning([{ finding_count: 0, resolved_count: 0 }])).toBeNull()
  })

  it('adds up several campaigns and says how many still have work', () => {
    const w = completionWarning([
      { finding_count: 4, resolved_count: 1 },
      { finding_count: 2, resolved_count: 2 },
      { finding_count: 1, resolved_count: 0 },
    ])
    expect(w).toEqual({ open: 4, total: 7, campaigns: 2 })
    expect(completionWarningText(w!, 3)).toBe('4 of 7 findings in 2 tasks are still open.')
  })

  it('uses the singular for one open finding', () => {
    const w = completionWarning([{ finding_count: 1, resolved_count: 0 }])
    expect(completionWarningText(w!)).toBe('1 of 1 finding is still open.')
  })
})

describe('progressPercent', () => {
  it('rounds the API value and clamps it to 0-100', () => {
    expect(progressPercent(33.3333)).toBe(33)
    expect(progressPercent(66.6666)).toBe(67)
    expect(progressPercent(0)).toBe(0)
    expect(progressPercent(120)).toBe(100)
    expect(progressPercent(null)).toBe(0)
    expect(progressPercent(undefined)).toBe(0)
  })
})

describe('fetchLiveCampaignCounts', () => {
  beforeEach(() => {
    mockGet.mockReset()
  })

  it('reads each campaign, whose GET recomputes the counts', async () => {
    mockGet.mockResolvedValueOnce({ finding_count: 4, resolved_count: 1 })
    const counts = await fetchLiveCampaignCounts(['c1'], {
      c1: { finding_count: 4, resolved_count: 0 },
    })
    expect(mockGet).toHaveBeenCalledWith('/api/v1/remediation/campaigns/c1')
    expect(counts).toEqual([{ finding_count: 4, resolved_count: 1 }])
  })

  it('keeps the page counts for a campaign it cannot read, so the question is still asked', async () => {
    mockGet.mockRejectedValueOnce(new Error('network'))
    const counts = await fetchLiveCampaignCounts(['c1'], {
      c1: { finding_count: 4, resolved_count: 0 },
    })
    expect(completionWarning(counts)).toEqual({ open: 4, total: 4, campaigns: 1 })
  })
})
