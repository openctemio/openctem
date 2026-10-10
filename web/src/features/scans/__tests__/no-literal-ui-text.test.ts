import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import en from '@/lib/i18n/dictionaries/en.json'
import vi from '@/lib/i18n/dictionaries/vi.json'
import { findLiteralUiText } from './literal-ui-text'

const ROOT = join(__dirname, '..')

function tsxFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : tsxFiles(path)
    return name.endsWith('.tsx') ? [path] : []
  })
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return name === '__tests__' ? [] : sourceFiles(path)
    return /\.tsx?$/.test(name) ? [path] : []
  })
}

describe('scans i18n catalog', () => {
  const enKeys = Object.keys(en).filter((k) => k.startsWith('scans.'))
  const viKeys = new Set(Object.keys(vi))

  it('has a Vietnamese value for every English scans key', () => {
    expect(enKeys.filter((k) => !viKeys.has(k))).toEqual([])
  })

  it('defines every literal scans key the code asks for', () => {
    const known = new Set(Object.keys(en))
    const missing = sourceFiles(ROOT).flatMap((file) =>
      [...readFileSync(file, 'utf8').matchAll(/\bt\(\s*'(scans\.[A-Za-z0-9_.:]+)'/g)]
        .map((m) => m[1])
        .filter((key) => !known.has(key))
        .map((key) => `${relative(ROOT, file)}: ${key}`)
    )
    expect(missing).toEqual([])
  })
})

describe('scans UI text goes through i18n', () => {
  it('has no literal JSX text, text attribute or toast message in features/scans', () => {
    const found = tsxFiles(ROOT).flatMap((file) =>
      findLiteralUiText(file, readFileSync(file, 'utf8')).map(
        (f) => `${relative(ROOT, file)}:${f.line} ${f.kind}: ${f.text}`
      )
    )
    // Every message is a t('scans.…') key with en and vi values.
    expect(found).toEqual([])
  })

  it('finds the shapes it guards against', () => {
    const src = `
      export const A = () => (
        <div title="Hello there" aria-label={'Close it'}>
          Some text
          {ok ? 'Yes please' : t('x')}
        </div>
      )
      toast.error('Failed to save')
      toast.success(t('ok'), { description: 'Also bad' })
    `
    const kinds = findLiteralUiText('x.tsx', src).map((f) => f.kind)
    expect(kinds).toEqual([
      'attribute',
      'attribute',
      'jsx-text',
      'expression',
      'toast',
      'expression',
    ])
  })
})
