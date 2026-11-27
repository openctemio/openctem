/**
 * The phone presentation of ActionMenu is chosen by fit
 * (web/docs/ui-style-contract.md, "Floating surfaces"): anchored for a short
 * menu that fits beside its trigger, the bottom sheet otherwise.
 */
import { describe, it, expect } from 'vitest'

import {
  PHONE_MENU_MAX_ITEMS,
  choosePhonePresentation,
  countedItems,
  phoneMenuHeight,
  type PhoneMenuShape,
  type PhoneMenuSpace,
} from '../action-menu-fit'

const row = (label = 80, reason?: number) => ({ label, reason })

function shape(over: Partial<PhoneMenuShape> = {}): PhoneMenuShape {
  return {
    rows: [row(), row()],
    headings: 0,
    separators: 0,
    hasSubmenu: false,
    hasInput: false,
    icons: false,
    ...over,
  }
}

// The /findings header More at 390: trigger near the top, most of the screen below.
const roomy: PhoneMenuSpace = { viewportWidth: 390, below: 600, above: 80 }

describe('choosePhonePresentation', () => {
  const cases: [string, PhoneMenuShape, PhoneMenuSpace, 'menu' | 'sheet'][] = [
    ['2 items, room below', shape(), roomy, 'menu'],
    ['6 items', shape({ rows: Array.from({ length: 6 }, () => row()) }), roomy, 'menu'],
    ['7 items', shape({ rows: Array.from({ length: 7 }, () => row()) }), roomy, 'sheet'],
    ['9 items', shape({ rows: Array.from({ length: 9 }, () => row()) }), roomy, 'sheet'],
    [
      '6 items and a single heading (does not count)',
      shape({ rows: Array.from({ length: 6 }, () => row()), headings: 1, separators: 1 }),
      roomy,
      'menu',
    ],
    [
      '6 items and two headings (the second counts)',
      shape({ rows: Array.from({ length: 6 }, () => row()), headings: 2, separators: 1 }),
      roomy,
      'sheet',
    ],
    [
      'separators do not count',
      shape({ rows: Array.from({ length: 6 }, () => row()), separators: 3 }),
      roomy,
      'menu',
    ],
    ['a submenu', shape({ hasSubmenu: true }), roomy, 'sheet'],
    ['a text field', shape({ hasInput: true }), roomy, 'sheet'],
    [
      'disabled items with reasons still count, and fit',
      shape({ rows: [row(80, 200), row(80, 200), row()] }),
      roomy,
      'menu',
    ],
    // 390 - 32 gutters - 26 chrome = 332 px of text per line.
    ['a label on two lines', shape({ rows: [row(600), row()] }), roomy, 'menu'],
    ['a label that needs three lines', shape({ rows: [row(700), row()] }), roomy, 'sheet'],
    ['a reason that needs three lines', shape({ rows: [row(80, 700)] }), roomy, 'sheet'],
    ['icons take room from the text', shape({ rows: [row(640)], icons: true }), roomy, 'sheet'],
    [
      'no room below, room above (flips)',
      shape(),
      { viewportWidth: 390, below: 40, above: 500 },
      'menu',
    ],
    [
      'no room either side (would scroll inside)',
      shape({ rows: Array.from({ length: 5 }, () => row()) }),
      { viewportWidth: 390, below: 150, above: 120 },
      'sheet',
    ],
    ['narrow 320 screen, short labels', shape(), { ...roomy, viewportWidth: 320 }, 'menu'],
  ]
  it.each(cases)('%s', (_name, s, space, expected) => {
    expect(choosePhonePresentation(s, space)).toBe(expected)
  })
})

describe('phoneMenuHeight', () => {
  it('counts 44 px rows, panel padding, headings and dividers', () => {
    expect(phoneMenuHeight(shape(), 390)).toBe(10 + 44 * 2)
    expect(phoneMenuHeight(shape({ headings: 1, separators: 1 }), 390)).toBe(10 + 32 + 9 + 88)
  })

  it('grows a row for a second label line and for a reason line', () => {
    // 12 + 2 x 20 = 52; 12 + 20 + 16 = 48.
    expect(phoneMenuHeight(shape({ rows: [row(600)] }), 390)).toBe(10 + 52)
    expect(phoneMenuHeight(shape({ rows: [row(80, 100)] }), 390)).toBe(10 + 48)
  })

  it('is null when a label needs more than two lines', () => {
    expect(phoneMenuHeight(shape({ rows: [row(10_000)] }), 390)).toBeNull()
  })
})

describe('countedItems', () => {
  it('counts rows and every heading after the first', () => {
    expect(countedItems({ rows: [row(), row()], headings: 0 })).toBe(2)
    expect(countedItems({ rows: [row(), row()], headings: 1 })).toBe(2)
    expect(countedItems({ rows: [row(), row()], headings: 3 })).toBe(4)
    expect(PHONE_MENU_MAX_ITEMS).toBe(6)
  })
})
