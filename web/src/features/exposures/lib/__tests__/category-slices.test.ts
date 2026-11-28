/**
 * A ring never gives two slices one colour: the tail past the palette folds
 * into Other (neutral), and the total is kept.
 */
import { describe, it, expect } from 'vitest'
import { categorySlices, OTHER_SLICE, OTHER_SLICE_COLOR } from '../category-slices'

const palette = ['c1', 'c2', 'c3', 'c4', 'c5']
const label = (k: string) => `L:${k}`

describe('categorySlices', () => {
  it('gives every slice its own colour and folds the tail into Other', () => {
    const counts = {
      certificate: 40,
      host: 120,
      service: 90,
      container: 5,
      ip_address: 200,
      subdomain: 150,
      repository: 7,
      website: 0,
    }
    const s = categorySlices(counts, palette, label, 'Other')
    expect(s.map((x) => x.key)).toEqual(['ip_address', 'subdomain', 'host', 'service', OTHER_SLICE])
    const colours = s.map((x) => x.color)
    expect(new Set(colours).size).toBe(colours.length)
    expect(s.at(-1)).toMatchObject({ name: 'Other', value: 40 + 7 + 5, color: OTHER_SLICE_COLOR })
    const total = s.reduce((n, x) => n + x.value, 0)
    expect(total).toBe(612)
    expect(s[0].name).toBe('L:ip_address')
  })

  it('needs no Other when the palette covers every category', () => {
    const s = categorySlices({ a: 1, b: 2 }, palette, label, 'Other')
    expect(s.map((x) => x.color)).toEqual(['c1', 'c2'])
    expect(s.some((x) => x.key === OTHER_SLICE)).toBe(false)
  })
})
