/**
 * Guard: the console never names a fixed host for itself.
 *
 * A self-hosted console runs on the operator's own domain, so a string such
 * as "app.openctem.io/" shown before an organization slug, or used as a
 * sample link, states an address that does not exist there. Use
 * `useAppOrigin()` / `useAppHost()` (src/hooks/use-app-origin.ts).
 */
import fs from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')
const FIXED_CONSOLE_HOST = /\bapp\.openctem\.(io|com)\b/

function sourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) {
      return e.name === '__tests__' || e.name === 'generated' ? [] : sourceFiles(p)
    }
    return /\.(ts|tsx)$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) ? [p] : []
  })
}

describe('console host guard', () => {
  it('no source file hard-codes the console host', () => {
    const offenders = sourceFiles(SRC_ROOT).filter((f) =>
      FIXED_CONSOLE_HOST.test(fs.readFileSync(f, 'utf8'))
    )
    expect(offenders.map((f) => path.relative(SRC_ROOT, f))).toEqual([])
  })
})
