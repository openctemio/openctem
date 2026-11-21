import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  dismissBody,
  dismissNoteMinLength,
  idempotencyKeyFor,
  previewLines,
  previewReason,
  readLastReason,
  summarizeDismiss,
  summarizeUndo,
  writeLastReason,
  type DismissResult,
} from '../bulk-dismiss'
import { en } from '@/lib/i18n/dictionaries'

// The catalog's English text, with {name} and ICU plural forms filled in.
function t(key: string, fallback?: string, params: Record<string, string | number> = {}) {
  let text = (en as Record<string, string>)[key] ?? fallback ?? key
  text = text.replace(
    /\{(\w+), plural, one \{([^}]*)\} other \{([^}]*)\}\}/g,
    (_, name: string, one: string, other: string) =>
      (Number(params[name]) === 1 ? one : other).replace(/#/g, String(params[name]))
  )
  return text.replace(/\{(\w+)\}/g, (_, name: string) => String(params[name] ?? `{${name}}`))
}

function result(over: Partial<DismissResult> = {}): DismissResult {
  return {
    status: 'preview',
    decided: [],
    grouped: null,
    skipped: [],
    counts: { decided: 0, grouped: 0, skipped: 0, budget_overflow: 0 },
    step_up_required: false,
    note_required: true,
    note_min_length: 1,
    replay: false,
    ...over,
  }
}

describe('bulk dismiss: the note rule (D4)', () => {
  it('is required until the server has answered', () => {
    expect(dismissNoteMinLength(undefined)).toBe(1)
    expect(dismissNoteMinLength(null)).toBe(1)
  })
  it('is optional only when the preview says so', () => {
    expect(dismissNoteMinLength({ note_required: false, note_min_length: 0 })).toBe(0)
  })
  it('takes the tier minimum, never below one character', () => {
    expect(dismissNoteMinLength({ note_required: true, note_min_length: 20 })).toBe(20)
    expect(dismissNoteMinLength({ note_required: true, note_min_length: 0 })).toBe(1)
  })
})

describe('bulk dismiss: the request', () => {
  it('sends ids, or the filter with the confirmed count', () => {
    const decision = {
      status: 'false_positive' as const,
      closureReason: 'detection_error',
      note: '  ',
    }
    expect(dismissBody({ kind: 'ids', ids: ['a', 'b'] }, decision)).toEqual({
      finding_ids: ['a', 'b'],
      status: 'false_positive',
      closure_reason: 'detection_error',
    })
    expect(
      dismissBody(
        { kind: 'filter', filter: { severity: 'low' }, total: 42 },
        {
          ...decision,
          status: 'accepted',
          closureReason: 'wont_fix',
          note: 'checked',
          expiresAt: 'x',
        }
      )
    ).toEqual({
      filter: { severity: 'low' },
      expected_count: 42,
      status: 'accepted',
      closure_reason: 'wont_fix',
      note: 'checked',
      expires_at: 'x',
    })
  })

  it('never sends an end date for a false positive', () => {
    const body = dismissBody(
      { kind: 'ids', ids: ['a'] },
      { status: 'false_positive', closureReason: 'detection_error', note: '', expiresAt: 'x' }
    )
    expect(body).not.toHaveProperty('expires_at')
  })

  it('previews with the first reason while none is chosen', () => {
    expect(previewReason('false_positive', '')).toBe('detection_error')
    expect(previewReason('accepted', '')).toBe('risk_accepted')
    expect(previewReason('false_positive', 'test_or_example_code')).toBe('test_or_example_code')
  })

  it('keeps the idempotency key across retries of one request, and changes it with the request', () => {
    let n = 0
    const mint = () => `k${++n}`
    const first = idempotencyKeyFor(null, { a: 1 }, mint)
    expect(first.key).toBe('k1')
    expect(idempotencyKeyFor(first, { a: 1 }, mint)).toBe(first)
    expect(idempotencyKeyFor(first, { a: 2 }, mint).key).toBe('k2')
  })
})

describe('bulk dismiss: the preview in plain words', () => {
  it('says what happens to each part', () => {
    const lines = previewLines(
      t,
      result({
        counts: { decided: 38, grouped: 4, skipped: 2, budget_overflow: 0 },
        skipped_items: [
          { id: 'a', reason: 'pending_request' },
          { id: 'b', reason: 'pending_request' },
        ],
      })
    )
    expect(lines.map((l) => l.text)).toEqual([
      '38 will be dismissed now.',
      '4 need a second person: they go to approval (one request).',
      '2 skipped: already waiting for approval.',
    ])
  })

  it('names no reason when the skipped ones differ, and leaves out empty parts', () => {
    const lines = previewLines(
      t,
      result({
        counts: { decided: 0, grouped: 5, skipped: 2, budget_overflow: 0 },
        skipped: [
          { id: 'a', reason: 'not_found' },
          { id: 'b', reason: 'cannot_move' },
        ],
      })
    )
    expect(lines.map((l) => l.text)).toEqual(['All 5 go to approval (one request).', '2 skipped.'])
  })
})

describe('bulk dismiss: the result and the undo', () => {
  it('reports what was dismissed, sent and skipped', () => {
    const s = summarizeDismiss(
      t,
      result({
        status: 'applied',
        counts: { decided: 3, grouped: 2, skipped: 1, budget_overflow: 0 },
        skipped: [{ id: 'x', reason: 'pending_request' }],
      })
    )
    expect(s).toEqual({
      kind: 'warning',
      message: 'Dismissed 3 findings',
      description: '2 sent for approval (one request). 1 skipped: already waiting for approval.',
    })
  })

  it('says when only an approval request was made, and when the daily limit moved some there', () => {
    const s = summarizeDismiss(
      t,
      result({ counts: { decided: 0, grouped: 7, skipped: 0, budget_overflow: 7 } })
    )
    expect(s.kind).toBe('success')
    expect(s.message).toBe('7 findings sent for approval')
    // The title says it once; the description only adds why.
    expect(s.description).not.toContain('sent for approval')
    expect(s.description).toContain('limit of 1,000')
  })

  it('is an error when nothing changed', () => {
    expect(
      summarizeDismiss(
        t,
        result({ counts: { decided: 0, grouped: 0, skipped: 3, budget_overflow: 0 } })
      ).kind
    ).toBe('error')
  })

  it('summarizes the undo', () => {
    expect(
      summarizeUndo(t, {
        bulk_id: 'b',
        reopened: ['a', 'b'],
        skipped: [{ id: 'c', reason: 'changed' }],
        group_canceled: true,
      })
    ).toEqual({
      kind: 'warning',
      message: 'Reopened 2 findings',
      description: 'The approval request was withdrawn. 1 was left as it is: it changed since.',
    })
  })
})

describe('bulk dismiss: the last reason', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    window.localStorage.clear()
  })

  it('remembers the last reason per status', () => {
    writeLastReason('false_positive', 'test_or_example_code')
    writeLastReason('accepted', 'wont_fix')
    expect(readLastReason('false_positive')).toBe('test_or_example_code')
    expect(readLastReason('accepted')).toBe('wont_fix')
  })

  it('ignores a stored value that is not a reason of that status', () => {
    window.localStorage.setItem(
      'openctem.findings.dismiss.lastReason',
      JSON.stringify({ false_positive: 'wont_fix' })
    )
    expect(readLastReason('false_positive')).toBe('')
  })

  it('works with storage switched off', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    expect(() => writeLastReason('false_positive', 'detection_error')).not.toThrow()
    expect(readLastReason('false_positive')).toBe('')
  })
})
