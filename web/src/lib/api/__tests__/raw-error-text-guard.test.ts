import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * A failure reaches a person through the shared mapper only
 * (`getErrorMessage`, `toastError`, `describeApiError`, `safeText` in
 * src/lib/api/error-message.ts): never the raw text of an error or of a
 * server-written status, which can carry ids, SQL, internal hosts or an
 * upstream body (research 258).
 */
const web = resolve(__dirname, '../../../..')
const roots = ['src', 'console/src'].map((r) => join(web, r))

const RULES: { name: string; re: RegExp }[] = [
  {
    name: 'toast of a raw error or result text',
    re: /toast(?:\.\w+)?\(\s*[\w?.]+\.(?:message|error|detail|status_message|error_message|last_error)\s*(?:\)|\|\||,)/,
  },
  {
    name: 'toast of a stored status text',
    re: /toast(?:\.\w+)?\([^)]*\.(?:status_message|error_message|last_error)\b/,
  },
  {
    name: 'JSX renders error.message',
    re: /\{\s*(?:err|error)\??\.message\s*\}|=\{\s*(?:err|error)\??\.message\s*\}/,
  },
]

/**
 * Reviewed: the text is the caller's own sentence or local validation, not
 * server or runtime text. Keys are `path:rule`; the list only shrinks.
 */
const REVIEWED = new Set<string>([
  // The mapper itself.
  'src/lib/api/error-message.ts:toast of a raw error or result text',
  // Success sentences the server or a server action writes (counts, no ids).
  'src/app/(dashboard)/(discovery)/scans/page.tsx:toast of a raw error or result text',
  // A summary the page builds from the bulk result (translated).
  'src/app/(dashboard)/findings/page.tsx:toast of a raw error or result text',
  // describeScanZoneError is the zone mapper (code -> translated sentence).
  'src/features/scan-zones/components/zone-sensors-dialog.tsx:toast of a raw error or result text',
  // The import dialog's error is set through safeText.
  'src/features/findings/components/import-results-dialog.tsx:JSX renders error.message',
  // Template validation lines from the server's validator: field + reason,
  // no ids (scanner template syntax errors the author must fix).
  'src/features/scanner-templates/components/add-scanner-template-dialog.tsx:JSX renders error.message',
])

function files(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '__tests__' || name.startsWith('.')) continue
    const p = join(dir, name)
    if (statSync(p).isDirectory()) files(p, out)
    else if (/\.(ts|tsx)$/.test(name) && !/\.(test|spec)\.tsx?$/.test(name)) out.push(p)
  }
  return out
}

describe('raw error text guard', () => {
  it('no raw error or status text reaches a toast or the page', () => {
    const found: string[] = []
    const seen = new Set<string>()
    for (const root of roots) {
      for (const f of files(root)) {
        const rel = relative(web, f)
        const lines = readFileSync(f, 'utf8').split('\n')
        lines.forEach((line, i) => {
          if (/^\s*(\/\/|\*)/.test(line)) return
          for (const rule of RULES) {
            if (!rule.re.test(line)) continue
            const key = `${rel}:${rule.name}`
            seen.add(key)
            if (!REVIEWED.has(key)) found.push(`${rel}:${i + 1} ${rule.name}: ${line.trim()}`)
          }
        })
      }
    }
    expect(
      found,
      'use getErrorMessage / toastError / safeText (src/lib/api/error-message.ts)'
    ).toEqual([])
    const stale = [...REVIEWED].filter((k) => !seen.has(k))
    expect(stale, 'stale REVIEWED entries: delete them').toEqual([])
  })
})
