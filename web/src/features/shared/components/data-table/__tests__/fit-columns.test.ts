import { describe, expect, it } from 'vitest'
import { fitColumnWidths } from '../fit-columns'

// The findings list at its always-on columns: 40 + 76 + 280 + 160 + 120 + 48 = 724.
const FINDINGS = [
  { id: 'select', width: 40, minWidth: 40 },
  { id: 'priority', width: 76, minWidth: 76 },
  { id: 'title', minWidth: 280 },
  { id: 'asset', width: 160, minWidth: 112 },
  { id: 'status', width: 120, minWidth: 120 },
  { id: 'actions', width: 48, minWidth: 48 },
]

describe('fitColumnWidths', () => {
  it('narrows nothing while the columns fit or before the frame is measured', () => {
    expect(fitColumnWidths(FINDINGS, 724).size).toBe(0)
    expect(fitColumnWidths(FINDINGS, 1000).size).toBe(0)
    expect(fitColumnWidths(FINDINGS, 0).size).toBe(0)
  })

  it('narrows a column with a range by exactly the missing width', () => {
    // 1024 px screen with the sidebar open: a 698 px frame.
    expect(fitColumnWidths(FINDINGS, 698)).toEqual(new Map([['asset', 134]]))
  })

  it('never goes below a floor: what is left scrolls', () => {
    expect(fitColumnWidths(FINDINGS, 600)).toEqual(new Map([['asset', 112]]))
  })

  it('shares the missing width in proportion to each range, exactly', () => {
    const cols = [
      { id: 'a', width: 200, minWidth: 100 },
      { id: 'b', width: 150, minWidth: 100 },
      { id: 'c', width: 100 },
    ]
    const fitted = fitColumnWidths(cols, 405)
    expect(fitted.get('a')).toBe(170)
    expect(fitted.get('b')).toBe(135)
    expect([...fitted.values()].reduce((s, w) => s + w, 0) + 100).toBe(405)
  })
})
