/**
 * Guard: an English string that puts a count before a plural noun ("{count}
 * assets") says "1 assets" for one item. Such strings carry an ICU plural
 * block instead: "{count, plural, one {# asset} other {# assets}}".
 * Vietnamese has no plural forms, so only the English catalog is checked.
 */
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { translate, registerDictionary } from '@/lib/i18n'

const EN_DIR = join(process.cwd(), 'src', 'lib', 'i18n', 'dictionaries', 'en')

/** Count variables, then an optional adjective, then a word ending in s. */
const COUNT_BEFORE_NOUN = new RegExp(
  '\\{(count|n|total|days|hours|minutes|seconds|weeks|months|added|removed|max|min|selected|remaining|done|failed|skipped|created|updated|deleted|matched|cap|limit|required|evaluated|closed|used|cols|received|requested|[a-z][a-zA-Z]*(?:Count|Total|Created|Updated)|(?!(?:status|alias|address|class|process|access|this|its|is|has|was|does|as)\\b)[a-z]+s)\\} ' +
    '(?:(?:new|open|more|other|unique|active|failed|closed|resolved|selected|matching|affected|related|known|existing|skipped|blocked|recent|duplicate) )?([a-z]+s)\\b',
  'g'
)
/** Words ending in s that are not plural nouns. */
const NOT_NOUN = new Set([
  'is',
  'this',
  'as',
  'does',
  'pass',
  'status',
  'stays',
  'uses',
  'creates',
  'was',
  'has',
  'its',
  'always',
  'waits',
  'breaks',
  'ms',
  'goes',
  'needs',
  'gets',
])
const PLURAL_BLOCK = /\{\w+,\s*plural,(?:\s*(?:=\d+|\w+)\s*\{[^{}]*\})+\s*\}/g

function withoutPluralBlocks(s: string): string {
  return s.replace(PLURAL_BLOCK, '')
}

describe('plural strings', () => {
  it('has no English count before a plural noun without a plural block', () => {
    const bad: string[] = []
    for (const file of readdirSync(EN_DIR).filter((f) => f.endsWith('.json'))) {
      const dict = JSON.parse(readFileSync(join(EN_DIR, file), 'utf8')) as Record<string, string>
      for (const [key, value] of Object.entries(dict)) {
        for (const m of withoutPluralBlocks(value).matchAll(COUNT_BEFORE_NOUN)) {
          if (!NOT_NOUN.has(m[2])) bad.push(`${key}: ${value}`)
        }
      }
    }
    expect(bad).toEqual([])
  })

  it('never fills a count by string replacement after t() (it would skip the plural)', () => {
    const src = join(process.cwd(), 'src')
    const offenders: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = join(dir, name)
        if (statSync(full).isDirectory()) {
          if (name !== '__tests__' && name !== 'node_modules') walk(full)
        } else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) {
          if (/\.replace\(\s*['"]\{(count|n|total)\}['"]/.test(readFileSync(full, 'utf8')))
            offenders.push(full.slice(src.length + 1))
        }
      }
    }
    walk(src)
    expect(offenders).toEqual([])
  })

  it('picks the branch and writes the number in the reader locale', () => {
    const en = { k: '{count, plural, one {# asset} other {# assets}} selected' }
    const vi = { k: '{count, plural, other {# tài sản}} đã chọn' }
    registerDictionary('en', en)
    registerDictionary('vi', vi)
    expect(translate(en, 'k', undefined, { count: 1 })).toBe('1 asset selected')
    expect(translate(en, 'k', undefined, { count: 12840 })).toBe('12,840 assets selected')
    expect(translate(vi, 'k', undefined, { count: 12840 })).toBe('12.840 tài sản đã chọn')
    expect(translate(en, 'k', undefined, { count: 12840 }, 'vi')).toBe('12.840 assets selected')
  })

  it('selects a branch for a count passed as text and shows that text', () => {
    const en = { k: '{count, plural, one {# asset} other {# assets}}' }
    expect(translate(en, 'k', undefined, { count: '1' })).toBe('1 asset')
    expect(translate(en, 'k', undefined, { count: '12,840' })).toBe('12,840 assets')
    expect(translate(en, 'k', undefined, { count: '99+' })).toBe('99+ assets')
  })
})
