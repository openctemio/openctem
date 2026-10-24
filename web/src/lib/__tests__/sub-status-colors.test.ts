import { describe, expect, it } from 'vitest'
import { TAG_PALETTE, TAG_SWATCH_CLASS } from '../tag-colors'
import { SUB_STATUS_TO_TAG_SWATCH, subStatusDotClass, subStatusSwatch } from '../sub-status-colors'

// The sixteen names the API stores (api findinglifecycle.Colors).
const API_COLORS = [
  'gray',
  'red',
  'orange',
  'amber',
  'yellow',
  'lime',
  'green',
  'emerald',
  'teal',
  'cyan',
  'sky',
  'blue',
  'indigo',
  'violet',
  'purple',
  'pink',
]

describe('sub-status colour fold', () => {
  it('maps every stored name onto the ten tag swatch names', () => {
    for (const c of API_COLORS) {
      expect((TAG_PALETTE as readonly string[]).includes(SUB_STATUS_TO_TAG_SWATCH[c])).toBe(true)
    }
    expect(Object.keys(SUB_STATUS_TO_TAG_SWATCH).sort()).toEqual([...API_COLORS].sort())
  })

  it('folds the near hues as designed and drops teal', () => {
    expect(subStatusSwatch('lime')).toBe('green')
    expect(subStatusSwatch('emerald')).toBe('green')
    expect(subStatusSwatch('sky')).toBe('blue')
    expect(subStatusSwatch('indigo')).toBe('blue')
    expect(subStatusSwatch('purple')).toBe('violet')
    expect(subStatusSwatch('teal')).toBe('cyan')
    expect(subStatusSwatch('gray')).toBe('grey')
    expect(Object.values(SUB_STATUS_TO_TAG_SWATCH)).not.toContain('teal')
  })

  it('uses the swatch dot class, and grey for unknown names', () => {
    expect(subStatusDotClass('red')).toBe(TAG_SWATCH_CLASS.red)
    expect(subStatusDotClass('rose')).toBe(TAG_SWATCH_CLASS.grey)
    expect(subStatusDotClass(undefined)).toBe(TAG_SWATCH_CLASS.grey)
  })
})
