import { describe, it, expect } from 'vitest'

import {
  MAX_DISPLAY_CHARS,
  hasHiddenCharacters,
  toDisplayText,
  toDisplayBlock,
} from '../untrusted-text'

// Built from code points so this file itself carries no invisible characters.
const c = (cp: number) => String.fromCodePoint(cp)
const RLO = c(0x202e)
const LRI = c(0x2066)
const ZWSP = c(0x200b)
const NUL = c(0x0000)
const BEL = c(0x0007)
const LS = c(0x2028)

describe('toDisplayText', () => {
  it('leaves ordinary text alone, including other scripts', () => {
    expect(toDisplayText('api.example.com:8443')).toBe('api.example.com:8443')
    expect(toDisplayText('مثال.example')).toBe('مثال.example')
    expect(toDisplayText('Tiếng Việt')).toBe('Tiếng Việt')
  })

  it('shows bidi overrides as escapes so they cannot reorder the row', () => {
    const spoof = `evil.com${RLO}moc.knab`
    expect(toDisplayText(spoof)).toBe('evil.com\\u{202E}moc.knab')
    expect(toDisplayText(`a${LRI}b`)).toBe('a\\u{2066}b')
    expect(hasHiddenCharacters(spoof)).toBe(true)
  })

  it('cannot fake a second line or hide text', () => {
    expect(toDisplayText('line one\nline two')).toBe('line one ⏎ line two')
    expect(toDisplayText('a\r\nb')).toBe('a ⏎ b')
    expect(toDisplayText(`a${LS}b`)).toBe('a\\u{2028}b')
    expect(toDisplayText(`pay${ZWSP}pal`)).toBe('pay\\u{200B}pal')
    expect(toDisplayText(`x${NUL}y${BEL}z`)).toBe('x\\u{0000}y\\u{0007}z')
    expect(toDisplayText('a\tb')).toBe('a b')
  })

  it('keeps markup as text (React renders it inert; nothing is decoded)', () => {
    expect(toDisplayText('<img src=x onerror=alert(1)>')).toBe('<img src=x onerror=alert(1)>')
    expect(toDisplayText('&lt;b&gt;')).toBe('&lt;b&gt;')
  })

  it('caps the length so a huge message cannot freeze the page', () => {
    const huge = 'A'.repeat(1_000_000)
    const out = toDisplayText(huge)
    expect(out.length).toBe(MAX_DISPLAY_CHARS + 1)
    expect(out.endsWith('…')).toBe(true)
    // A cut never leaves half a surrogate pair.
    const emoji = 'x'.repeat(9) + c(0x1f600)
    expect(toDisplayText(emoji, 10)).toBe('x'.repeat(9) + '…')
  })

  it('treats empty values as empty', () => {
    expect(toDisplayText(undefined)).toBe('')
    expect(toDisplayText(null)).toBe('')
    expect(hasHiddenCharacters('plain')).toBe(false)
  })
})

describe('toDisplayBlock', () => {
  it('keeps line breaks and tabs, escapes bidi, ANSI and lone CR', () => {
    const out = toDisplayBlock(
      `a\r\nb\tc\rd${String.fromCodePoint(0x202e)}e${String.fromCodePoint(0x1b)}[2J`
    )
    expect(out).toBe('a\nb\tc\\u{000D}d\\u{202E}e\\u{001B}[2J')
  })

  it('never interprets markup', () => {
    expect(toDisplayBlock('<b>x</b>')).toBe('<b>x</b>')
  })

  it('caps very long output with a note', () => {
    const out = toDisplayBlock('A'.repeat(100), 10)
    expect(out.startsWith('A'.repeat(10))).toBe(true)
    expect(out).toContain('cut for display')
    expect(toDisplayBlock(null)).toBe('')
  })
})
