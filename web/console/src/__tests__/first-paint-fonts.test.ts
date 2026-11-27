import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { firstPaintFonts } from '../lib/first-paint-fonts'

/**
 * The console preloads the Inter files of its first paint. Each one must be a
 * file the stylesheet declares (a renamed file would preload a 404 and leave
 * the real one late), and a Vietnamese page must get every subset its letters
 * come from.
 */
const css = readFileSync(path.resolve(__dirname, '../../../src/styles/fonts.css'), 'utf8')
const faces = [...css.matchAll(/@font-face\s*{([^}]*)}/g)].map((m) => m[1])
const interFiles = faces
  .filter((f) => /font-family:\s*'Inter'/.test(f))
  .map((f) => /url\('([^']+)'\)/.exec(f)?.[1])
  .filter(Boolean) as string[]

function rangeOf(file: string): string {
  const face = faces.find((f) => f.includes(`url('${file}')`)) ?? ''
  return /unicode-range:([^;]*);/.exec(face)?.[1] ?? ''
}

describe('first paint fonts', () => {
  it('preloads only Inter files the stylesheet declares', () => {
    for (const locale of ['en', 'vi', 'xx']) {
      for (const href of firstPaintFonts(locale)) expect(interFiles).toContain(href)
    }
  })

  it('preloads the Latin file for English and every Vietnamese subset for Vietnamese', () => {
    expect(firstPaintFonts('en')).toEqual(['/fonts/inter-latin-wght-normal.woff2'])
    const vi = firstPaintFonts('vi').map(rangeOf).join(',')
    // ASCII, the ă/đ/ơ/ư block and the stacked tone marks (U+1EA0..U+1EF9).
    expect(vi).toMatch(/U\+0000-00FF/)
    expect(vi).toMatch(/U\+0100-02BA/)
    expect(vi).toMatch(/U\+1EA0-1EF9/)
  })

  it('declares the size-adjusted fallback right after Inter in the sans stack', () => {
    expect(css).toMatch(/font-family:\s*'Inter Fallback'/)
    const theme = readFileSync(path.resolve(__dirname, '../../../src/styles/theme.css'), 'utf8')
    expect(theme).toMatch(/--font-sans:\s*'Inter',\s*'Inter Fallback',/)
  })
})
