import { describe, expect, it } from 'vitest'
import { widePackSpans } from '../layout'

const cols = (ws: number[], columns: number, perRow: number) =>
  widePackSpans(
    ws.map((w) => ({ w })),
    columns,
    perRow
  ).map((p) => p.column)

describe('dashboard on a wide screen', () => {
  it('packs the CTEM template four to a row only where a run has four widgets', () => {
    // key figures, loop, fix next + new vs fixed, levers, four halves
    const ctem = [12, 12, 6, 6, 12, 6, 6, 6, 6]
    expect(cols(ctem, 4, 4)).toEqual([
      'span 12 / span 12',
      'span 12 / span 12',
      'span 6 / span 6',
      'span 6 / span 6',
      'span 12 / span 12',
      'span 3 / span 3',
      'span 3 / span 3',
      'span 3 / span 3',
      'span 3 / span 3',
    ])
  })

  it('splits a run evenly: four three to a row are two rows of two, six are two rows of three', () => {
    expect(cols([6, 6, 6, 6], 4, 3)).toEqual(Array(4).fill('span 6 / span 6'))
    expect(cols([6, 6, 6, 6, 6, 6], 4, 3)).toEqual(Array(6).fill('span 4 / span 4'))
    expect(cols([6, 6, 6, 6, 6], 4, 3)).toEqual([
      'span 4 / span 4',
      'span 4 / span 4',
      'span 4 / span 4',
      'span 6 / span 6',
      'span 6 / span 6',
    ])
  })

  it('keeps tiles already four to a row, full-width widgets and order', () => {
    expect(cols([3, 3, 3, 3, 12], 4, 4)).toEqual([
      'span 3 / span 3',
      'span 3 / span 3',
      'span 3 / span 3',
      'span 3 / span 3',
      'span 12 / span 12',
    ])
    // A lone half between full-width widgets stays a half: no row is filled with one widget.
    expect(cols([12, 6, 12], 2, 3)).toEqual([
      'span 12 / span 12',
      'span 6 / span 6',
      'span 12 / span 12',
    ])
  })

  it('a packed widget is one row tall; an unpacked one keeps its rows', () => {
    const placed = widePackSpans([{ w: 6 }, { w: 6 }, { w: 6 }, { w: 12 }], 2, 3)
    expect(placed.map((p) => p.packed)).toEqual([true, true, true, false])
  })
})
