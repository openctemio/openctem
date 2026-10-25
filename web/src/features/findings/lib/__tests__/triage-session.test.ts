import { describe, expect, it } from 'vitest'
import {
  TRIAGE_DEFAULT_QUERY,
  TRIAGE_MAX_ITEMS,
  changedElsewhere,
  mergeWindow,
  moveTo,
  needsWindow,
  newSession,
  nextUndecided,
  parseSession,
  popUndo,
  pushUndo,
  progress,
  readSession,
  safeReturnPath,
  setOutcome,
  startSession,
  triageHref,
  triageQuery,
  writeSession,
  type TriageItem,
} from '../triage-session'
import { refillStartPage } from '../../hooks/use-triage-session'

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`
const item = (n: number, extra: Partial<TriageItem> = {}): TriageItem => ({
  id: id(n),
  title: `finding ${n}`,
  status: 'new',
  rowVersion: 1,
  ...extra,
})
const items = (from: number, to: number) =>
  Array.from({ length: to - from + 1 }, (_, i) => item(from + i))

function memoryStore() {
  const m = new Map<string, string>()
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
  }
}

describe('triageQuery', () => {
  it('keeps filter and sort params and drops paging', () => {
    expect(triageQuery('status=new&severity=critical&sort=-created_at&page=3&per_page=100')).toBe(
      'status=new&severity=critical&sort=-created_at'
    )
  })
  it('drops names that are not list contract params and empty values', () => {
    expect(triageQuery('status=new&__proto__=x&Bad=1&a.b=2&q=')).toBe('status=new')
  })
  it('falls back to the Needs triage queue', () => {
    expect(triageQuery('')).toBe(TRIAGE_DEFAULT_QUERY)
    expect(triageQuery('page=2')).toBe(TRIAGE_DEFAULT_QUERY)
    expect(triageHref('')).toBe('/findings/triage?status=new')
  })
})

describe('safeReturnPath (no open redirect)', () => {
  it.each([
    ['/findings', '/findings'],
    ['/findings?severity=critical&q=a%20b', '/findings?severity=critical&q=a%20b'],
  ])('keeps the findings list %s', (raw, want) => {
    expect(safeReturnPath(raw)).toBe(want)
  })
  it.each([
    'https://evil.example/findings',
    '//evil.example/findings',
    '/\\evil.example',
    '/findings/../admin',
    '/findingsx',
    '/findings/123',
    '/settings',
    'javascript:alert(1)',
    '/findings?x=1\n',
    '\t/findings',
    '',
    null,
    42,
    { href: '/findings' },
    `/findings?${'a'.repeat(5000)}`,
  ])('turns %j into the plain list', (raw) => {
    expect(safeReturnPath(raw)).toBe('/findings')
  })
})

describe('session storage', () => {
  it('round-trips a session for the same query only', () => {
    const store = memoryStore()
    startSession('status=new', '/findings?severity=high', store)
    const s = readSession('status=new', store)
    expect(s).toMatchObject({
      query: 'status=new',
      returnTo: '/findings?severity=high',
      fromList: true,
    })
    expect(readSession('status=in_review', store)).toBeNull()
  })
  it('a crafted session cannot carry a foreign return path or bad ids', () => {
    const raw = JSON.stringify({
      v: 1,
      query: 'status=new',
      returnTo: 'https://evil.example',
      fromList: true,
      items: [item(1), { id: '../../x', title: 'bad' }, { id: id(2) }],
      index: 99,
      outcomes: { [id(1)]: 'confirmed', 'not-an-id!': 'confirmed' },
      total: 'many',
      exhausted: false,
    })
    const s = parseSession(raw)!
    expect(s.returnTo).toBe('/findings')
    expect(s.items.map((i) => i.id)).toEqual([id(1)])
    expect(s.index).toBe(1)
    expect(Object.keys(s.outcomes)).toEqual([id(1)])
    expect(s.total).toBe(1)
  })
  it('malformed or foreign values read as no session', () => {
    expect(parseSession('{')).toBeNull()
    expect(parseSession(JSON.stringify({ v: 2, query: 'status=new', items: [] }))).toBeNull()
    expect(parseSession(null)).toBeNull()
  })
  it('works without storage (blocked or private)', () => {
    const throwing = {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => {
        throw new Error('blocked')
      },
      removeItem: () => {},
    }
    expect(readSession('status=new', throwing)).toBeNull()
    expect(() => writeSession(newSession('status=new', '/findings', false), throwing)).not.toThrow()
  })
})

describe('queue mechanics', () => {
  it('appends a window in order, without ids already seen', () => {
    let s = newSession('status=new', '/findings', true)
    s = mergeWindow(s, items(1, 25), 60, false).session
    expect(s.items).toHaveLength(25)
    expect(s.total).toBe(60)
    // Ids 20-25 were skipped and still match; 26-44 are new.
    const r = mergeWindow(s, items(20, 44), 40, false)
    expect(r.added).toBe(19)
    expect(r.session.items.map((i) => i.id).slice(24, 27)).toEqual([id(25), id(26), id(27)])
    expect(r.session.total).toBe(44 + (40 - 6 - 19))
  })
  it('the last page ends the queue', () => {
    const s = mergeWindow(newSession('status=new', '/findings', true), items(1, 3), 3, true).session
    expect(s.exhausted).toBe(true)
    expect(s.total).toBe(3)
  })
  it('never keeps more than the session cap', () => {
    const big = Array.from({ length: TRIAGE_MAX_ITEMS + 10 }, (_, i) => item(i + 1))
    const s = mergeWindow(newSession('status=new', '/findings', true), big, 9999, false).session
    expect(s.items).toHaveLength(TRIAGE_MAX_ITEMS)
    expect(s.exhausted).toBe(true)
  })
  it('auto-advance passes over decided findings', () => {
    let s = mergeWindow(newSession('status=new', '/findings', true), items(1, 5), 5, true).session
    s = setOutcome(s, id(2), 'confirmed')
    s = setOutcome(s, id(3), 'skipped')
    expect(nextUndecided(s, 0)).toBe(3)
    expect(nextUndecided(moveTo(s, 4), 4)).toBe(-1)
  })
  it('reads the next window five findings before the end', () => {
    const s = mergeWindow(
      newSession('status=new', '/findings', true),
      items(1, 25),
      80,
      false
    ).session
    expect(needsWindow(moveTo(s, 19))).toBe(false)
    expect(needsWindow(moveTo(s, 20))).toBe(true)
    expect(needsWindow({ ...moveTo(s, 24), exhausted: true })).toBe(false)
  })
  it('a refill starts where the seen findings that still match end', () => {
    let s = mergeWindow(
      newSession('status=new', '/findings', true),
      items(1, 75),
      200,
      false
    ).session
    // 50 confirmed (left the view), 25 skipped (still in it): page 1.
    for (let n = 1; n <= 50; n++) s = setOutcome(s, id(n), 'confirmed')
    for (let n = 51; n <= 75; n++) s = setOutcome(s, id(n), 'skipped')
    expect(refillStartPage(s)).toBe(1)
    // 75 skipped: start on page 3, not page 1.
    for (let n = 1; n <= 50; n++) s = setOutcome(s, id(n), 'skipped')
    expect(refillStartPage(s)).toBe(3)
  })
  it('counts progress by outcome', () => {
    let s = mergeWindow(newSession('status=new', '/findings', true), items(1, 6), 86, false).session
    s = setOutcome(s, id(1), 'confirmed')
    s = setOutcome(s, id(2), 'assigned')
    s = setOutcome(s, id(3), 'fp_requested')
    s = setOutcome(s, id(4), 'accept_requested')
    s = setOutcome(s, id(5), 'skipped')
    s = setOutcome(s, id(6), 'changed')
    expect(progress(moveTo(s, 5))).toEqual({
      position: 6,
      total: 86,
      decided: 2,
      sentForApproval: 2,
      skipped: 1,
      changed: 1,
    })
    expect(progress(moveTo(s, 6)).position).toBe(0)
  })
})

describe('changedElsewhere', () => {
  it('flags a newer version with another status the person did not make', () => {
    expect(changedElsewhere(item(1), { status: 'confirmed', row_version: 2 }, undefined)).toBe(true)
  })
  it('ignores the person own decision, an unchanged status and an older read', () => {
    expect(changedElsewhere(item(1), { status: 'confirmed', row_version: 2 }, 'confirmed')).toBe(
      false
    )
    expect(changedElsewhere(item(1), { status: 'new', row_version: 5 }, undefined)).toBe(false)
    expect(
      changedElsewhere(
        item(1, { rowVersion: 3 }),
        { status: 'confirmed', row_version: 3 },
        undefined
      )
    ).toBe(false)
  })
})

describe('undo stack', () => {
  it('keeps the newest ten and pops the newest first', () => {
    let s = newSession('status=new', '/findings', true)
    for (let n = 1; n <= 12; n++) s = pushUndo(s, { id: id(n), outcome: 'skipped' })
    expect(s.undo).toHaveLength(10)
    expect(s.undo[0].id).toBe(id(3))
    const { session, entry } = popUndo(s)
    expect(entry?.id).toBe(id(12))
    expect(session.undo).toHaveLength(9)
    expect(popUndo(newSession('status=new', '/findings', true)).entry).toBeUndefined()
  })
  it('a stored stack keeps only well-formed entries', () => {
    const raw = JSON.stringify({
      v: 1,
      query: 'status=new',
      items: [],
      undo: [
        { id: id(1), outcome: 'fp_requested', approvalId: id(9) },
        { id: id(2), outcome: 'deleted' },
        { id: id(3), outcome: 'fp_requested', approvalId: '../x' },
        { id: id(4), outcome: 'confirmed', previousStatus: 'new; drop' },
        { id: id(5), outcome: 'assigned', previousAssigneeId: null },
      ],
    })
    expect(parseSession(raw)!.undo.map((u) => u.id)).toEqual([id(1), id(5)])
  })
})
