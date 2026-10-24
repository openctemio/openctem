import { describe, expect, it } from 'vitest'
import { TAG_PALETTE } from '../tag-colors'
import {
  CAPABILITY_COLOR_CHOICES,
  CAPABILITY_COLOR_TO_SWATCH,
  capabilitySwatch,
} from '../capability-colors'

// Every name the old capability surfaces knew (badge, card, table, detail
// panel, create and edit dialogs).
const OLD_NAMES = [
  'blue',
  'purple',
  'green',
  'red',
  'orange',
  'cyan',
  'yellow',
  'lime',
  'teal',
  'indigo',
  'fuchsia',
  'amber',
  'violet',
  'sky',
  'slate',
  'gray',
  'emerald',
  'pink',
]

describe('capability colour migration', () => {
  it('maps every old name onto the ten swatch names', () => {
    for (const n of OLD_NAMES) {
      expect(TAG_PALETTE as readonly string[]).toContain(capabilitySwatch(n))
    }
  })

  it('folds as designed and never yields teal', () => {
    expect(capabilitySwatch('purple')).toBe('violet')
    expect(capabilitySwatch('indigo')).toBe('blue')
    expect(capabilitySwatch('teal')).toBe('cyan')
    expect(capabilitySwatch('fuchsia')).toBe('pink')
    expect(capabilitySwatch('slate')).toBe('grey')
    expect(capabilitySwatch('gray')).toBe('grey')
    expect(Object.values(CAPABILITY_COLOR_TO_SWATCH)).not.toContain('teal')
  })

  it('keeps palette names as they are and falls back to grey', () => {
    for (const n of TAG_PALETTE) expect(capabilitySwatch(n)).toBe(n)
    expect(capabilitySwatch('nope')).toBe('grey')
    expect(capabilitySwatch(undefined)).toBe('grey')
  })

  it('offers exactly the ten swatch names to authors', () => {
    expect([...CAPABILITY_COLOR_CHOICES]).toEqual([...TAG_PALETTE])
    expect(CAPABILITY_COLOR_CHOICES as readonly string[]).not.toContain('teal')
  })
})
