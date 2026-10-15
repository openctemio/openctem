/**
 * Guard: the console never hard-codes the product name in text people read.
 *
 * The brand is configuration (src/lib/brand.ts, api/docs/architecture/brand.md):
 * text names the product through `{product}` in the catalogs or `useBrand()`.
 * This test parses every source file and every catalog value and fails on
 * the literal default name in a string, template or JSX text outside the
 * allow list below. Comments are not text and are not checked.
 */
import fs from 'node:fs'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')
const NAME = /OpenCTEM/

/** Files that may name the default brand, with the reason. */
const ALLOWED_FILES: Record<string, string> = {
  'lib/brand.ts': 'the default brand itself (DEFAULT_BRAND, UPSTREAM_NAME)',
  'assets/logo.tsx':
    "the built-in mark's own label; BrandMark/BrandLogoFull pass the brand name over it",
}

/** Text that is a technical identifier, not the product's display name. */
const TECHNICAL = [
  // The CI check-run name the API posts to GitHub; branch protection rules
  // match it, so it never follows the brand.
  /OpenCTEM gate/g,
  // A decision reason the API returns verbatim (pkg/domain/ticketmap), matched
  // as a key to pick its translation.
  /finding is closed; reopen it in OpenCTEM/g,
]

function strip(text: string): string {
  return TECHNICAL.reduce((t, re) => t.replace(re, ''), text)
}

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) {
      if (e.name === '__tests__' || e.name === 'generated' || e.name === 'node_modules') continue
      sourceFiles(p, out)
    } else if (
      /\.tsx?$/.test(e.name) &&
      !/\.(test|spec)\.tsx?$/.test(e.name) &&
      !e.name.endsWith('.d.ts')
    ) {
      out.push(p)
    }
  }
  return out
}

/** Every literal text in a file: strings, template parts and JSX text. */
function literalTexts(file: string, code: string): { line: number; text: string }[] {
  const sf = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const found: { line: number; text: string }[] = []
  const visit = (n: ts.Node) => {
    if (
      ts.isStringLiteral(n) ||
      ts.isNoSubstitutionTemplateLiteral(n) ||
      ts.isTemplateHead(n) ||
      ts.isTemplateMiddle(n) ||
      ts.isTemplateTail(n) ||
      ts.isJsxText(n)
    ) {
      found.push({ line: sf.getLineAndCharacterOfPosition(n.getStart()).line + 1, text: n.text })
    }
    ts.forEachChild(n, visit)
  }
  visit(sf)
  return found
}

describe('no hard-coded product name in user-visible text', () => {
  it('source strings and JSX text use the brand', () => {
    const offenders: string[] = []
    for (const file of sourceFiles(SRC_ROOT)) {
      const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/')
      if (ALLOWED_FILES[rel]) continue
      const code = fs.readFileSync(file, 'utf8')
      // Parse only files that mention the name at all (most do not).
      if (!NAME.test(code)) continue
      for (const { line, text } of literalTexts(file, code)) {
        if (NAME.test(strip(text))) offenders.push(`${rel}:${line}: ${text.trim().slice(0, 80)}`)
      }
    }
    expect(
      offenders,
      'Name the product with {product} in the catalog or useBrand(), or allow-list a technical identifier with its reason'
    ).toEqual([])
  }, 60_000)

  it('catalog values use {product}', () => {
    const dir = path.join(SRC_ROOT, 'lib/i18n/dictionaries')
    const offenders: string[] = []
    for (const lang of fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory())) {
      for (const f of fs.readdirSync(path.join(dir, lang.name))) {
        const cat = JSON.parse(fs.readFileSync(path.join(dir, lang.name, f), 'utf8')) as Record<
          string,
          string
        >
        for (const [k, v] of Object.entries(cat)) {
          if (NAME.test(strip(v))) offenders.push(`${lang.name}/${f}: ${k}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('finds a planted name, and not one in a comment', () => {
    const texts = literalTexts(
      'x.tsx',
      "// OpenCTEM in a comment\nconst a = 'Welcome to OpenCTEM'\nconst b = <p>About OpenCTEM</p>\n"
    )
    expect(texts.filter((t) => NAME.test(t.text)).map((t) => t.line)).toEqual([2, 3])
  })
})
