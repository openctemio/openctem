import { describe, expect, it } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { findHardcodedText, isProse } from './helpers/hardcoded-text'

/**
 * Guard (owner rule): no user-visible text is hard-coded in the console. Use
 * t('key', 'English') with en and vi values in web/src/lib/i18n/dictionaries.
 */
const ROOT = path.resolve(__dirname, '..')

// Files not checked, each with the reason.
const ALLOW_FILES: Record<string, string> = {
  // rewritten in the users/catalog branch
  'app/(console)/users': 'rewritten in the users/catalog branch',
  'features/admin-console/components/platform-user-': 'rewritten in the users/catalog branch',
  'features/admin-console/api/use-platform-users.ts': 'rewritten in the users/catalog branch',
  'app/(console)/system/content-packs': 'rewritten in the users/catalog branch',
  'features/admin-console/components/add-content-pack-dialog.tsx':
    'rewritten in the users/catalog branch',
  'features/admin-console/components/content-lint-report.tsx':
    'rewritten in the users/catalog branch',
}

function files(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) return e.name === '__tests__' ? [] : files(p)
    return /\.tsx$/.test(e.name) ? [p] : []
  })
}

describe('hard-coded text detector', () => {
  it('flags prose and ignores product names, codes and env vars', () => {
    expect(isProse('Save changes')).toBe(true)
    expect(isProse('SAML')).toBe(false)
    expect(isProse('SIGNUP_MODE')).toBe(false)
    expect(isProse('10.0.0.0/8')).toBe(false)
    expect(isProse('https://idp.example.com')).toBe(false)
    expect(isProse('OIDC / SAML')).toBe(false)
    expect(isProse('Client secret')).toBe(true)
    expect(isProse('—')).toBe(false)
  })

  it('finds JSX text, text props, string branches and toasts', () => {
    const src = `
      export function A({ x }: { x: boolean }) {
        return (<div title="Close it" aria-label={'Close now'}>
          Hello there
          <span>{x ? 'Yes please' : t('k', 'Fine')}</span>
          <b>{t('a', 'Translated')}</b>
          <i placeholder="https://x.example">OIDC</i>
          {toast.success('Saved it')}
        </div>)
      }`
    expect(findHardcodedText(src, 'a.tsx').map((h) => h.text)).toEqual([
      'Close it',
      'Close now',
      'Hello there',
      'Yes please',
      'Saved it',
    ])
  })
})

describe('console text', () => {
  it('is never hard-coded in a component', () => {
    const offenders: string[] = []
    for (const f of files(ROOT)) {
      const rel = path.relative(ROOT, f).split(path.sep).join('/')
      if (Object.keys(ALLOW_FILES).some((a) => rel.startsWith(a))) continue
      for (const h of findHardcodedText(fs.readFileSync(f, 'utf8'), rel))
        offenders.push(`${h.file}:${h.line} ${JSON.stringify(h.text)}`)
    }
    expect(offenders).toEqual([])
  })
})
