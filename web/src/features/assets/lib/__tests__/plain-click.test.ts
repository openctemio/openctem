import { describe, it, expect } from 'vitest'
import { isPlainLeftClick } from '../plain-click'

const base = {
  button: 0,
  metaKey: false,
  ctrlKey: false,
  shiftKey: false,
  altKey: false,
  defaultPrevented: false,
}

describe('isPlainLeftClick', () => {
  it('accepts an unmodified primary click', () => {
    expect(isPlainLeftClick(base)).toBe(true)
  })
  it.each([
    ['ctrl', { ctrlKey: true }],
    ['cmd', { metaKey: true }],
    ['shift', { shiftKey: true }],
    ['alt', { altKey: true }],
    ['middle button', { button: 1 }],
    ['already handled', { defaultPrevented: true }],
  ])('rejects %s', (_n, patch) => {
    expect(isPlainLeftClick({ ...base, ...patch })).toBe(false)
  })
})
