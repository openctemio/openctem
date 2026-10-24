import { describe, expect, it } from 'vitest'
import { tagColorForName } from '../tag-colors'

describe('tagColorForName', () => {
  it('keeps palette names and maps the legacy words', () => {
    expect(tagColorForName('red')).toBe('red')
    expect(tagColorForName('Purple')).toBe('violet')
    expect(tagColorForName('indigo')).toBe('violet')
    expect(tagColorForName('emerald')).toBe('green')
    expect(tagColorForName('slate')).toBe('grey')
    expect(tagColorForName('gray')).toBe('grey')
  })
  it('falls back to grey', () => {
    expect(tagColorForName('chartreuse')).toBe('grey')
    expect(tagColorForName(undefined)).toBe('grey')
  })
})
