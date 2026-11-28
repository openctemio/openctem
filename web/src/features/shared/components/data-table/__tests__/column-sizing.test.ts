import { describe, expect, it } from 'vitest'
import {
  allocateColumnWidths,
  columnFloor,
  columnsToDrop,
  distribute,
  HYSTERESIS,
  NAME_COMFORT,
  KIND_SIZING,
  mergeNatural,
  nameFloor,
  type SizingColumn,
} from '../column-sizing'
import { KIND_LAYOUT, type ColumnKind } from '../column-meta'

const sum = (m: Map<string, number> | null) => [...(m?.values() ?? [])].reduce((s, w) => s + w, 0)

// A findings-like row: priority, title, location, severity, status, due, created, row menu.
const findings = (title: number, location: number): SizingColumn[] => [
  { id: 'select', kind: 'select', fixed: 40 },
  { id: 'priority', kind: 'priority', natural: 60 },
  { id: 'title', kind: 'name', natural: title },
  { id: 'asset', kind: 'asset', natural: location },
  { id: 'severity', kind: 'severity', natural: 104 },
  { id: 'status', kind: 'status', natural: 150 },
  { id: 'due', kind: 'due', natural: 120 },
  { id: 'created', kind: 'date', natural: 112 },
  { id: 'actions', kind: 'actions', natural: 44 },
]

describe('KIND_SIZING', () => {
  it('covers every column kind with a floor at or below its cap', () => {
    for (const kind of Object.keys(KIND_LAYOUT) as ColumnKind[]) {
      const s = KIND_SIZING[kind]
      expect(s, kind).toBeDefined()
      expect(s.min, kind).toBeLessThanOrEqual(s.max)
      // Only columns that may truncate or wrap take a share of the room.
      if (s.weight > 0) expect(s.shrink, kind).toBe(true)
    }
  })
})

describe('distribute', () => {
  it('shares by weight in whole px and never past an item room', () => {
    const out = distribute(100, [
      { id: 'a', weight: 3, room: 1000 },
      { id: 'b', weight: 1, room: 10 },
    ])
    expect(out.get('b')).toBe(10)
    expect(out.get('a')).toBe(90)
  })
  it('gives nothing to items without weight or room', () => {
    const out = distribute(50, [
      { id: 'a', weight: 0, room: 100 },
      { id: 'b', weight: 1, room: 0 },
    ])
    expect(sum(out)).toBe(0)
  })
  it('handles amounts smaller than the number of items', () => {
    const out = distribute(1, [
      { id: 'a', weight: 1, room: 5 },
      { id: 'b', weight: 1, room: 5 },
    ])
    expect(sum(out)).toBe(1)
  })
})

describe('allocateColumnWidths', () => {
  it('waits for a frame and for every measurement', () => {
    expect(allocateColumnWidths(findings(400, 200), 0)).toBeNull()
    expect(allocateColumnWidths([{ id: 'x', kind: 'text' }], 1000)).toBeNull()
  })

  it('fills the frame exactly and gives the spare room to the title', () => {
    const w = allocateColumnWidths(findings(400, 200), 1800, 1920)!
    expect(sum(w)).toBe(1800)
    // Whole values keep their content width.
    expect(w.get('severity')).toBe(104)
    expect(w.get('status')).toBe(150)
    expect(w.get('created')).toBe(112)
    // Title (weight 4) gets more of the spare room than location (weight 2).
    expect(w.get('title')! - 400).toBeGreaterThan(w.get('asset')! - 200)
  })

  it('gives a long value its content before sharing whitespace', () => {
    // Location 500 natural (cap 360): with room it is shown whole.
    const w = allocateColumnWidths(findings(300, 500), 2400, 2560)!
    expect(w.get('asset')).toBeGreaterThanOrEqual(500)
    expect(sum(w)).toBe(2400)
  })

  it('shrinks the flexible columns first, whole values never below content', () => {
    const w = allocateColumnWidths(findings(900, 300), 1000, 1280)!
    expect(sum(w)).toBe(1000)
    expect(w.get('severity')).toBe(104)
    expect(w.get('due')).toBe(120)
    expect(w.get('created')).toBe(112)
    expect(w.get('title')).toBeGreaterThanOrEqual(192)
    expect(w.get('asset')).toBeGreaterThanOrEqual(128)
  })

  it('then the other shrinkable columns, then overflows (the frame scrolls)', () => {
    const w = allocateColumnWidths(findings(900, 300), 700, 768)!
    expect(w.get('title')).toBe(nameFloor(768))
    expect(w.get('asset')).toBe(128)
    // A status is a whole value: it keeps its content.
    expect(w.get('status')).toBe(150)
    expect(sum(w)).toBeGreaterThan(700)
    expect(w.get('severity')).toBe(104)
  })

  it('keeps a page override exact', () => {
    const cols = findings(400, 200).map((c) => (c.id === 'status' ? { ...c, fixed: 133 } : c))
    for (const frame of [700, 1200, 2400]) {
      expect(allocateColumnWidths(cols, frame, frame)!.get('status')).toBe(133)
    }
  })

  it('honours a page floor and cap override', () => {
    const cols = findings(900, 300).map((c) => (c.id === 'title' ? { ...c, min: 260 } : c))
    expect(allocateColumnWidths(cols, 700, 768)!.get('title')).toBe(260)
  })

  it('spreads the room over content columns when no column is flexible', () => {
    const cols: SizingColumn[] = [
      { id: 'a', kind: 'date', natural: 100 },
      { id: 'b', kind: 'number', natural: 60 },
      { id: 'actions', kind: 'actions', natural: 40 },
    ]
    const w = allocateColumnWidths(cols, 600)!
    expect(sum(w)).toBe(600)
    expect(w.get('actions')).toBe(40)
  })

  it('is stable: the same inputs give the same widths', () => {
    const a = allocateColumnWidths(findings(420, 180), 1500, 1600)
    const b = allocateColumnWidths(findings(420, 180), 1500, 1600)
    expect([...a!]).toEqual([...b!])
  })

  it('stays O(columns) fast on wide tables', () => {
    const cols: SizingColumn[] = Array.from({ length: 40 }, (_, i) => ({
      id: `c${i}`,
      kind: i % 3 === 0 ? 'name' : 'text',
      natural: 80 + i * 7,
    }))
    const t0 = performance.now()
    for (let i = 0; i < 200; i++) allocateColumnWidths(cols, 1000 + i * 10, 1920)
    expect(performance.now() - t0).toBeLessThan(500)
  })
})

describe('mergeNatural', () => {
  const kinds = new Map<string, ColumnKind>([
    ['title', 'name'],
    ['status', 'status'],
  ])
  it('takes a first measurement', () => {
    const out = mergeNatural(new Map(), new Map([['title', 300]]), kinds, true)
    expect(out.get('title')).toBe(300)
  })
  it('keeps the title once rows were measured (no jump on page or sort)', () => {
    const kept = new Map([['title', 300]])
    expect(mergeNatural(kept, new Map([['title', 500]]), kinds, true)).toBe(kept)
    expect(mergeNatural(kept, new Map([['title', 200]]), kinds, true)).toBe(kept)
  })
  it('grows a whole value past the hysteresis only, never shrinks it', () => {
    const kept = new Map([['status', 120]])
    expect(mergeNatural(kept, new Map([['status', 120 + HYSTERESIS]]), kinds, true)).toBe(kept)
    expect(mergeNatural(kept, new Map([['status', 100]]), kinds, true)).toBe(kept)
    expect(mergeNatural(kept, new Map([['status', 140]]), kinds, true).get('status')).toBe(140)
  })
  it('does not freeze on a header-only measurement (no rows yet)', () => {
    const kept = new Map([['title', 80]])
    // Headers only: nothing changes yet; the first real rows replace it.
    expect(mergeNatural(kept, new Map([['title', 90]]), kinds, false)).toBe(kept)
  })
})

describe('columnsToDrop', () => {
  // A short title (under its floor): the title counts at its floor.
  const cols = () =>
    findings(180, 200).map((c) =>
      c.id === 'severity' ? { ...c, drop: 1 } : c.id === 'due' ? { ...c, drop: 2 } : c
    )
  const floors = (ids: Set<string>) =>
    cols()
      .filter((c) => !ids.has(c.id))
      .reduce((s, c) => s + columnFloor(c, 1920), 0)

  it('drops nothing when the floors fit', () => {
    expect(columnsToDrop(cols(), 1400, 1920).size).toBe(0)
  })
  it('drops by order, 1 first, until the floors fit', () => {
    const all = floors(new Set())
    expect([...columnsToDrop(cols(), all - 10, 1920)]).toEqual(['severity'])
    expect([...columnsToDrop(cols(), all - 110, 1920)]).toEqual(['severity', 'due'])
  })
  it('drops an optional column before cutting a long title under NAME_COMFORT', () => {
    const long = cols().map((c) => (c.id === 'title' ? { ...c, natural: 900 } : c))
    const all = floors(new Set())
    // Room for every floor, but the title would get only its floor.
    expect([...columnsToDrop(long, all + 68, 1920)]).toEqual(['severity'])
    expect(columnsToDrop(long, all + (NAME_COMFORT - 192), 1920).size).toBe(0)
  })
  it('never drops a column without an order (the frame scrolls instead)', () => {
    expect([...columnsToDrop(cols(), 200, 1920)]).toEqual(['severity', 'due'])
  })
  it('counts a whole value at its content and a title at its floor', () => {
    expect(columnFloor({ id: 's', kind: 'severity', natural: 120 })).toBe(120)
    expect(columnFloor({ id: 't', kind: 'name', natural: 900 }, 1920)).toBe(192)
    expect(columnFloor({ id: 'x', kind: 'status', fixed: 99 })).toBe(99)
  })
})
