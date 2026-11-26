import { describe, expect, it } from 'vitest'
import type { ReceiptResponse } from '../../api/receipts-api'
import { foldNoFindingRuns, isNoFindingsRun, receiptIssue, sumChanges } from '../import-rows'

const zero = {
  created: 0,
  updated: 0,
  reactivated: 0,
  closed: 0,
  skipped: 0,
  failed: 0,
  suppressed: 0,
}

function rc(id: string, over: Partial<ReceiptResponse> = {}): ReceiptResponse {
  return {
    id,
    status: 'completed',
    source: { kind: 'scan_run', ref: id },
    tool: 'subfinder',
    received: 0,
    counts: zero,
    assets: { created: 1, updated: 2, recorded_on_name: 0 },
    errors: [],
    started_at: '2026-11-20T10:00:00Z',
    ...over,
  } as ReceiptResponse
}

describe('receiptIssue', () => {
  it('shows no status for a completed receipt without problems', () => {
    expect(receiptIssue(rc('a'))).toBeNull()
  })
  it('names failed, running and partly stored receipts', () => {
    expect(receiptIssue(rc('a', { status: 'failed' }))).toBe('failed')
    expect(receiptIssue(rc('a', { status: 'processing' }))).toBe('processing')
    expect(receiptIssue(rc('a', { status: 'queued' }))).toBe('queued')
    expect(receiptIssue(rc('a', { counts: { ...zero, failed: 2 } }))).toBe('partial')
    expect(
      receiptIssue(
        rc('a', { errors: [{ index: 0, code: 'parse_error' }] } as Partial<ReceiptResponse>)
      )
    ).toBe('partial')
  })
})

describe('isNoFindingsRun', () => {
  it('is a completed run that received and changed no finding (assets allowed)', () => {
    expect(isNoFindingsRun(rc('a'))).toBe(true)
  })
  it('is not a run that did anything to findings, failed, or still runs', () => {
    expect(isNoFindingsRun(rc('a', { received: 3, counts: { ...zero, updated: 3 } }))).toBe(false)
    expect(isNoFindingsRun(rc('a', { counts: { ...zero, closed: 4 } }))).toBe(false)
    expect(isNoFindingsRun(rc('a', { status: 'failed' }))).toBe(false)
    expect(isNoFindingsRun(rc('a', { status: 'processing' }))).toBe(false)
    expect(isNoFindingsRun(rc('a', { outcomes: { merged: 1 } }))).toBe(false)
    expect(
      isNoFindingsRun(
        rc('a', {
          closing: {
            considered: 2,
            closed: { not_found: 2 },
            proposed: 0,
            kept: {},
            hosts: 1,
            hosts_unfinished: 0,
            hosts_local_checks_failed: 0,
          },
        } as Partial<ReceiptResponse>)
      )
    ).toBe(false)
  })
})

describe('foldNoFindingRuns', () => {
  it('folds the no-finding runs of one tool into one row at the newest, keeping every run', () => {
    const changed = rc('n1', { tool: 'nuclei', received: 5, counts: { ...zero, created: 5 } })
    const rows = foldNoFindingRuns([
      rc('s1'),
      changed,
      rc('s2'),
      rc('d1', { tool: 'dnsx' }),
      rc('s3'),
    ])
    expect(rows.map((r) => r.id)).toEqual(['runs:s1', 'n1', 'd1'])
    expect(rows[0].runs?.map((r) => r.id)).toEqual(['s1', 's2', 's3'])
    // A lone no-finding run keeps a row of its own.
    expect(rows[2].runs).toBeUndefined()
    // Nothing is lost: every receipt is in exactly one row.
    const all = rows.flatMap((r) => r.runs ?? [r.receipt]).map((r) => r.id)
    expect(all.sort()).toEqual(['d1', 'n1', 's1', 's2', 's3'])
  })
  it('never folds across source kinds, or a failed run', () => {
    const rows = foldNoFindingRuns([
      rc('s1'),
      rc('u1', { source: { kind: 'upload', ref: 'u1' } }),
      rc('f1', { status: 'failed' }),
    ])
    expect(rows.map((r) => r.id)).toEqual(['s1', 'u1', 'f1'])
  })
  it('sums the assets of the folded runs', () => {
    expect(sumChanges([rc('a'), rc('b')]).assets).toBe(6)
  })
})
