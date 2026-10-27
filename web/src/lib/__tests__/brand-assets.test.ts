import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Gate for the logo: the retired shapes and spelling must not come back, and
 * every SVG of the brand folder is the one listed (hash) in its manifest.
 */
const WEB = path.resolve(__dirname, '../../..')
const API = path.resolve(WEB, '../api')
const BRAND_DIR = path.join(WEB, 'src/assets/brand')

const SCAN_ROOTS = [
  path.join(WEB, 'src'),
  path.join(WEB, 'console/src'),
  path.join(WEB, 'public'),
  path.join(WEB, 'e2e'),
  path.join(API, 'pkg/email'),
  path.join(API, 'internal/infra/templates'),
]
const TEXT = /\.(tsx?|jsx?|mjs|json|svg|html|tmpl|go|md|css)$/

/** Retired logo: the round-1 and earlier shapes and the old spelling. Built from parts so this file does not contain them. */
const RETIRED: [string, string][] = [
  ['the old spelling', 'open' + 'Ctem'],
  ['the old C arc', '92.22 ' + '39.86'],
  ['the old wordmark paths', 'M19 46Q14.4 ' + '46 11 44'],
  ['the old wordmark paths', 'M196.05 ' + '14.8V21.1'],
  ['the round-1 centred square', 'x="46" y="46" ' + 'width="28"'],
  ['the old e-mail blue name', '#2563' + 'eb; }'],
]

function* files(dir: string): Generator<string> {
  if (!existsSync(dir)) return
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next') continue
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) yield* files(full)
    else if (TEXT.test(name)) yield full
  }
}

describe('brand assets gate', () => {
  it('no retired logo shape or spelling anywhere in web, console or the e-mail templates', () => {
    const hits: string[] = []
    for (const root of SCAN_ROOTS) {
      for (const f of files(root)) {
        if (f === __filename) continue
        const text = readFileSync(f, 'utf8')
        for (const [what, needle] of RETIRED) {
          if (text.includes(needle)) hits.push(`${path.relative(WEB, f)}: ${what}`)
        }
      }
    }
    expect(hits).toEqual([])
  })

  it('every svg of the brand folder and of public/ is listed in manifest.json with its hash', () => {
    const manifest = JSON.parse(readFileSync(path.join(BRAND_DIR, 'manifest.json'), 'utf8')) as {
      files: Record<string, string>
    }
    const svgs = readdirSync(BRAND_DIR).filter((n) => n.endsWith('.svg'))
    expect(Object.keys(manifest.files).sort()).toEqual([...svgs].sort())
    for (const n of svgs) {
      const sha = createHash('sha256')
        .update(readFileSync(path.join(BRAND_DIR, n)))
        .digest('hex')
      expect(manifest.files[n], n).toBe(sha)
    }
    const stray = [...files(path.join(WEB, 'public'))].filter((f) => f.endsWith('.svg'))
    expect(stray.map((f) => path.relative(WEB, f))).toEqual([])
  })

  it('the generated files match the generator (no hand edits)', () => {
    execFileSync('node', [path.join(WEB, 'scripts/brand-gen.mjs'), '--check'], {
      cwd: WEB,
      stdio: 'pipe',
    })
  })
})
