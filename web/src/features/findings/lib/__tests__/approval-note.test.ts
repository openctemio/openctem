import { afterEach, describe, expect, it, vi } from 'vitest'
import { isNoteRequired, noteMinLength, readLastReason, writeLastReason } from '../approval-note'

describe('noteMinLength (the note rule)', () => {
  it('is optional only when the person decides alone on a finding that is not serious', () => {
    expect(noteMinLength({ can_decide_alone: true, material: false })).toBe(0)
    expect(isNoteRequired({ can_decide_alone: true, material: false })).toBe(false)
  })

  it('is required on a serious finding, even decided alone', () => {
    expect(noteMinLength({ can_decide_alone: true, material: true })).toBe(1)
  })

  it('is required when a second person approves, with the tier minimum', () => {
    expect(
      noteMinLength({
        can_decide_alone: false,
        material: false,
        evaluation: { min_note_length: 20 },
      })
    ).toBe(20)
    expect(noteMinLength({ can_decide_alone: false, material: false })).toBe(1)
  })

  it('is required while the policy is unknown', () => {
    expect(noteMinLength(undefined)).toBe(1)
    expect(noteMinLength(null)).toBe(1)
  })
})

describe('noteMinLength from a bulk Dismiss preview', () => {
  it('is optional only when the preview says so', () => {
    expect(noteMinLength({ note_required: false, note_min_length: 0 })).toBe(0)
    expect(isNoteRequired({ note_required: false, note_min_length: 0 })).toBe(false)
  })
  it('takes the tier minimum, never below one character', () => {
    expect(noteMinLength({ note_required: true, note_min_length: 20 })).toBe(20)
    expect(noteMinLength({ note_required: true, note_min_length: 0 })).toBe(1)
  })
})

describe('the last reason (every dismiss form)', () => {
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
