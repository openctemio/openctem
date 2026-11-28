import { describe, expect, it } from 'vitest'

import {
  FIX_REFUSAL_CODES,
  summarizeApprovalBulk,
  summarizeBulkResult,
  summarizeFixDecision,
} from '../bulk-result'
import { getDictionary, translate } from '@/lib/i18n'

const en = getDictionary('en')
const t = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(en, key, fallback, vars)
const vi = getDictionary('vi')
const tVi = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(vi, key, fallback, vars)

// POST /findings/bulk/status and /bulk/assign answer 200 with
// { updated, failed, errors } even when nothing changed. The page used to toast
// "Updated N findings" on any 200, so a bulk change to false positive that the
// approval gate refused for every finding reported success.
describe('summarizeBulkResult', () => {
  it('reports full success', () => {
    expect(summarizeBulkResult({ updated: 3, failed: 0 }, 3, 'updated', t)).toEqual({
      kind: 'success',
      message: 'Updated 3 findings',
    })
  })

  it('reports a partial failure with the first reason, without the finding id', () => {
    const r = summarizeBulkResult(
      {
        updated: 1,
        failed: 2,
        errors: [
          '01a0fd40-a7c3-7119-980e-9abf5e203d0f: changing to false positive needs approval from a user with the findings:approve permission; submit an approval request instead',
          'x: other',
        ],
      },
      3,
      'updated',
      t
    )
    expect(r.kind).toBe('warning')
    expect(r.message).toBe('Updated 1 of 3 findings. 2 not changed')
    expect(r.description).toBe(
      'changing to false positive needs approval from a user with the findings:approve permission; submit an approval request instead'
    )
  })

  it('reports a total failure as an error', () => {
    const r = summarizeBulkResult({ updated: 0, failed: 2, errors: ['id: nope'] }, 2, 'updated', t)
    expect(r.kind).toBe('error')
    expect(r.message).toBe('No findings were changed')
    expect(r.description).toBe('nope')
  })

  it('falls back to the requested count when the body has no counts', () => {
    expect(summarizeBulkResult(undefined, 2, 'assigned', t)).toEqual({
      kind: 'success',
      message: 'Assigned 2 findings',
    })
  })

  it('uses the singular for one finding', () => {
    expect(summarizeBulkResult({ updated: 1, failed: 0 }, 1, 'assigned', t).message).toBe(
      'Assigned 1 finding'
    )
  })

  it('speaks the app language', () => {
    const r = summarizeBulkResult({ updated: 0, failed: 1, errors: ['x: y'] }, 1, 'updated', tVi)
    expect(r.message).not.toBe('No findings were changed')
    expect(summarizeBulkResult({ updated: 2, failed: 0 }, 2, 'updated', tVi).message).toContain('2')
  })
})

// POST /approvals/bulk/approve and /bulk/reject report every id with an
// outcome and a stable code; the toast gives the counts and, for what was not
// decided, each plain reason with how many it held.
describe('summarizeApprovalBulk', () => {
  it('reports a clean approval', () => {
    expect(
      summarizeApprovalBulk(
        {
          results: [{ outcome: 'approved' }, { outcome: 'approved' }, { outcome: 'signed' }],
          approved: 2,
          signed: 1,
          rejected: 0,
          skipped: 0,
          failed: 0,
        },
        t
      )
    ).toEqual({
      kind: 'success',
      message: '2 approved, 1 waiting for more approvals',
      description: undefined,
    })
  })

  it('lists skipped and failed items with plain reasons, most common first', () => {
    const s = summarizeApprovalBulk(
      {
        results: [
          { outcome: 'approved' },
          { outcome: 'skipped', code: 'own_request' },
          { outcome: 'skipped', code: 'not_found' },
          { outcome: 'skipped', code: 'not_found' },
          { outcome: 'failed', code: 'step_up_required' },
        ],
        approved: 1,
        signed: 0,
        rejected: 0,
        skipped: 3,
        failed: 1,
      },
      t
    )
    expect(s.kind).toBe('warning')
    expect(s.message).toBe('1 approved, 3 skipped, 1 not decided')
    expect(s.description).toBe(
      'Not found, or outside what you can see: 2. Your own request: someone else decides it: 1. Needs its own sign-in check: approve it on its own: 1'
    )
  })

  it('is an error when nothing was decided', () => {
    const s = summarizeApprovalBulk(
      {
        results: [{ outcome: 'skipped', code: 'not_pending' }],
        approved: 0,
        signed: 0,
        rejected: 0,
        skipped: 1,
        failed: 0,
      },
      t
    )
    expect(s.kind).toBe('error')
    expect(s.description).toBe('Already decided: 1')
  })

  it('reports rejections in Vietnamese', () => {
    const s = summarizeApprovalBulk(
      { results: [], approved: 0, signed: 0, rejected: 2, skipped: 0, failed: 0 },
      tVi
    )
    expect(s).toEqual({ kind: 'success', message: '2 đã từ chối', description: undefined })
  })
})

// "0 done" is never a success: a 200 with nothing changed used to toast
// "Updated 0 findings" / "0 findings verified" in green.
describe('nothing done is not a success', () => {
  it('summarizeBulkResult with nothing updated and nothing refused', () => {
    const s = summarizeBulkResult({ updated: 0, failed: 0 }, 2, 'updated', t)
    expect(s.kind).toBe('warning')
    expect(s.message).toBe('No findings were changed')
  })

  it('summarizeApprovalBulk with nothing decided and nothing refused', () => {
    const s = summarizeApprovalBulk(
      { results: [], approved: 0, signed: 0, rejected: 0, skipped: 0, failed: 0 },
      t
    )
    expect(s.kind).toBe('warning')
  })
})

// Approve / Reject of claimed fixes in the verification queue
// (POST /findings/actions/verify and /reject-fix).
describe('summarizeFixDecision', () => {
  it('says why nothing was verified (the critical finding on prod)', () => {
    const s = summarizeFixDecision(
      {
        updated: 0,
        refused: 1,
        reasons: { evidence_required: 1 },
        rows: [{ finding_id: 'f1', code: 'evidence_required' }],
      },
      'verified',
      t
    )
    expect(s.kind).toBe('error')
    expect(s.message).toBe(
      'Nothing was verified: A critical, P0 or known-exploited finding needs a retest that confirms the fix, or the verification checklist completed by another person'
    )
    expect(s.message).not.toMatch(/^0 /)
  })

  it('warns on a partial verify with every reason and its count', () => {
    const s = summarizeFixDecision(
      { updated: 1, refused: 2, reasons: { checklist_required: 1, changed: 1 } },
      'verified',
      t
    )
    expect(s.kind).toBe('warning')
    expect(s.message).toBe('1 of 3 verified')
    expect(s.description).toContain('2 not changed:')
    expect(s.description).toContain('Changed meanwhile: reload and try again (1)')
  })

  it('lists the reasons when several kept everything back', () => {
    const s = summarizeFixDecision(
      { updated: 0, refused: 3, reasons: { not_found: 1, evidence_required: 2 } },
      'rejected',
      t
    )
    expect(s.kind).toBe('error')
    expect(s.message).toBe('Nothing was rejected')
    expect(s.description?.startsWith('A critical')).toBe(true)
  })

  it('is a warning, not a success, when nothing was waiting any more', () => {
    const s = summarizeFixDecision({ updated: 0, refused: 0, reasons: {} }, 'verified', t)
    expect(s.kind).toBe('warning')
  })

  it('is a success only when every finding moved', () => {
    expect(summarizeFixDecision({ updated: 2, refused: 0 }, 'verified', t)).toEqual({
      kind: 'success',
      message: '2 findings verified',
    })
  })

  it('reads in Vietnamese', () => {
    const s = summarizeFixDecision(
      { updated: 0, refused: 1, reasons: { not_found: 1 } },
      'verified',
      tVi
    )
    expect(s.message).toBe(
      'Không có gì được xác minh: Không tìm thấy, hoặc nằm ngoài phạm vi bạn được xem'
    )
  })

  it('has an English and a Vietnamese sentence for every refusal code', () => {
    for (const code of FIX_REFUSAL_CODES) {
      expect(en[`findings.fixRefusal.${code}`], code).toBeTruthy()
      expect(vi[`findings.fixRefusal.${code}`], code).toBeTruthy()
    }
  })
})
