/**
 * The findings list is translated: no JSX text, accessible name, placeholder or
 * toast in these files is a hard-coded string, and every literal `t('key')`
 * resolves in both the English and the Vietnamese catalog.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'
import { en, vi } from '@/lib/i18n/dictionaries'

const FILES = [
  'app/(dashboard)/findings/page.tsx',
  'features/findings/components/finding-row-menu.tsx',
  'features/findings/components/finding-phone-card.tsx',
  'features/findings/components/findings-empty-state.tsx',
  'features/shared/components/data-table/data-table.tsx',
  'features/shared/components/data-table/data-table-column-header.tsx',
  'features/shared/components/data-table/data-table-groups.tsx',
  'features/shared/components/facet-filter-panel.tsx',
  'features/shared/components/bulk-action-bar.tsx',
  'features/shared/components/filter-button.tsx',
  'features/shared/components/filter-sheet.tsx',
  'features/shared/components/error-state.tsx',
  'features/saved-views/components/saved-views-menu.tsx',
  'features/sla/components/sla-status-badge.tsx',
]

const A11Y_ATTRS = new Set(['aria-label', 'title', 'placeholder', 'alt', 'label', 'description'])
const read = (f: string) => readFileSync(join(process.cwd(), 'src', f), 'utf8')

function hardCoded(file: string): string[] {
  const src = read(file)
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const found: string[] = []
  const words = (t: string) => /[A-Za-z]{2}/.test(t)
  const visit = (n: ts.Node) => {
    if (ts.isJsxText(n) && words(n.getText().replace(/\s+/g, ' ').trim())) {
      found.push(`text: ${n.getText().trim()}`)
    }
    if (
      ts.isJsxAttribute(n) &&
      n.initializer &&
      ts.isStringLiteral(n.initializer) &&
      A11Y_ATTRS.has(n.name.getText()) &&
      words(n.initializer.text)
    ) {
      found.push(`${n.name.getText()}: ${n.initializer.text}`)
    }
    if (
      ts.isCallExpression(n) &&
      /^toast\.(success|error|info|warning)$/.test(n.expression.getText()) &&
      n.arguments[0] &&
      (ts.isStringLiteral(n.arguments[0]) || ts.isNoSubstitutionTemplateLiteral(n.arguments[0]))
    ) {
      found.push(`toast: ${n.arguments[0].getText()}`)
    }
    ts.forEachChild(n, visit)
  }
  visit(sf)
  return found
}

describe('findings list i18n', () => {
  for (const file of FILES) {
    it(`${file}: no hard-coded text`, () => {
      expect(hardCoded(file)).toEqual([])
    })

    it(`${file}: every literal t() key exists in en and vi`, () => {
      const keys = [...read(file).matchAll(/\bt\(\s*['"`]([A-Za-z0-9_.]+)['"`]/g)].map((m) => m[1])
      const missing = keys.filter((k) => !(k in en) || !(k in vi))
      expect(missing).toEqual([])
    })
  }
})
