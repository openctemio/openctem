import { describe, expect, it } from 'vitest'
import { PIN_FLEX_MAX, PIN_START_SHARE, pinStartColumns } from '../pin-columns'

const findings = [
  { id: 'select', width: 40 },
  { id: 'priorityClass', pin: 'start' as const, width: 76 },
  { id: 'title', pin: 'start' as const, minWidth: 280 },
  { id: 'asset', width: 160 },
  { id: 'status', width: 120 },
  { id: 'actions', width: 48 },
]

describe('pinStartColumns', () => {
  it('freezes checkbox, Priority and the title when the group fits the share of the frame', () => {
    const pins = pinStartColumns(findings, 1114)
    expect([...pins.keys()]).toEqual(['select', 'priorityClass', 'title'])
    expect(pins.get('select')).toEqual({ start: 0, last: false })
    expect(pins.get('priorityClass')).toEqual({ start: 40, last: false })
    const title = pins.get('title')!
    expect(title.start).toBe(116)
    expect(title.last).toBe(true)
    // Capped at what the share leaves, never above the flexible maximum.
    expect(title.maxWidth).toBe(Math.min(PIN_FLEX_MAX, Math.floor(1114 * PIN_START_SHARE - 116)))
    expect(116 + title.maxWidth!).toBeLessThanOrEqual(1114 * PIN_START_SHARE)
  })

  it('caps a wide frame title at the flexible maximum', () => {
    expect(pinStartColumns(findings, 2400).get('title')?.maxWidth).toBe(PIN_FLEX_MAX)
  })

  it('freezes only checkbox and Priority when the title floor does not fit the share', () => {
    // 40 + 76 + 280 = 396 > 0.45 * 800 = 360
    const pins = pinStartColumns(findings, 800)
    expect([...pins.keys()]).toEqual(['select', 'priorityClass'])
    expect(pins.get('priorityClass')?.last).toBe(true)
  })

  it('switches at the share: 880 holds the title floor, 879 does not', () => {
    expect(pinStartColumns(findings, 880).has('title')).toBe(true)
    expect(pinStartColumns(findings, 879).has('title')).toBe(false)
  })

  it('freezes the first marked column even before the frame is measured', () => {
    expect([...pinStartColumns(findings, 0).keys()]).toEqual(['select', 'priorityClass'])
  })

  it('a table without marked columns freezes its first data column, as before', () => {
    const pins = pinStartColumns(
      [{ id: 'select' }, { id: 'name' }, { id: 'owner', width: 160 }, { id: 'actions' }],
      1000
    )
    expect([...pins.keys()]).toEqual(['select', 'name'])
    expect(pins.get('name')).toEqual({ start: 40, last: true, fallback: true })
  })

  it('without a checkbox column the group starts at 0, and actions are never frozen at the start', () => {
    const pins = pinStartColumns(
      [{ id: 'actions' }, { id: 'name', pin: 'start', width: 200 }],
      1000
    )
    expect([...pins.keys()]).toEqual(['name'])
    expect(pins.get('name')?.start).toBe(0)
  })
})
