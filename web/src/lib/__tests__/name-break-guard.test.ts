/**
 * Names and addresses never break inside a word (acceptance review K1):
 * "Payments platform" read "Paym|ents platf|orm" on every asset phone card
 * because the name carried `break-all`.
 *
 * - `break-all` (breaks every word at any letter, even when it fits) is kept only for
 *   machine values drawn in a mono font (hashes, keys, tokens, code): a line
 *   that uses them must also say `mono`, `<code` or `<pre`.
 * - Names, host names, e-mail addresses and URLs use `break-words` with
 *   `<BreakText>` (features/shared/components/break-text), which adds break
 *   opportunities at their separators only.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = join(__dirname, '..', '..')
const SKIP_DIR = new Set(['__tests__', '__mocks__', 'generated', 'dictionaries'])
const ANYWHERE = /\bbreak-all\b|wordBreak:\s*['"]break-all/
const MACHINE = /mono|<code|<pre/

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return SKIP_DIR.has(name) ? [] : sources(path)
    if (/\.(test|spec|stories)\.tsx?$/.test(name) || name.endsWith('.d.ts')) return []
    return /\.tsx?$/.test(name) ? [path] : []
  })
}

export function anywhereBreaks(source: string): number[] {
  return source
    .split('\n')
    .flatMap((line, i) => (ANYWHERE.test(line) && !MACHINE.test(line) ? [i + 1] : []))
}

describe('names break only at separators', () => {
  it('flags break-all on a name and allows it on a mono value', () => {
    expect(anywhereBreaks('<p className="break-all font-medium">{a.name}</p>')).toEqual([1])
    expect(anywhereBreaks('<code className="break-all font-mono">{hash}</code>')).toEqual([])
    expect(anywhereBreaks('<p className="break-words"><BreakText>{a.name}</BreakText></p>')).toEqual([])
  })

  it('no text outside mono/code values breaks at any letter', () => {
    const hits = sources(SRC).flatMap((file) =>
      anywhereBreaks(readFileSync(file, 'utf8')).map((n) => `${relative(SRC, file)}:${n}`)
    )
    expect(hits).toEqual([])
  })
})
