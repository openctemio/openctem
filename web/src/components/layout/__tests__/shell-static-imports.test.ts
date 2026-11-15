import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import ts from 'typescript'

/**
 * The code every dashboard route downloads first is the static import closure
 * of the two layouts. Modules that only matter once something opens or fails
 * (a dialog, the command menu, the toaster, the QR code) belong behind
 * next/dynamic or import(); this test fails when a static import brings one
 * back into the shell, which Web CI's route JavaScript budget would otherwise
 * report only as a number.
 */
const SRC = resolve(__dirname, '../../..')
const ROOTS = ['app/(dashboard)/layout.tsx', 'app/layout.tsx'].map((f) => join(SRC, f))
const SUFFIXES = ['.ts', '.tsx', '/index.ts', '/index.tsx']

function resolveLocal(from: string, spec: string): string | null {
  const base = spec.startsWith('@/') ? join(SRC, spec.slice(2)) : resolve(dirname(from), spec)
  for (const s of ['', ...SUFFIXES]) {
    const p = base + s
    if (existsSync(p) && statSync(p).isFile()) return p
  }
  return null
}

/** Source files and package names reached by static imports from the layouts. */
function staticClosure() {
  const files = new Set<string>(ROOTS)
  const packages = new Set<string>()
  const queue = [...ROOTS]
  while (queue.length) {
    const file = queue.shift()!
    if (!/\.tsx?$/.test(file)) continue
    const sf = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true)
    for (const st of sf.statements) {
      let spec: string | undefined
      if (ts.isImportDeclaration(st)) {
        if (st.importClause?.isTypeOnly) continue
        const nb = st.importClause?.namedBindings
        if (
          nb &&
          ts.isNamedImports(nb) &&
          nb.elements.length &&
          nb.elements.every((e) => e.isTypeOnly)
        )
          continue
        spec = (st.moduleSpecifier as ts.StringLiteral).text
      } else if (ts.isExportDeclaration(st) && st.moduleSpecifier && !st.isTypeOnly) {
        spec = (st.moduleSpecifier as ts.StringLiteral).text
      }
      if (!spec) continue
      if (spec.startsWith('.') || spec.startsWith('@/')) {
        const target = resolveLocal(file, spec)
        if (target && !files.has(target)) {
          files.add(target)
          queue.push(target)
        }
      } else {
        packages.add(
          spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]
        )
      }
    }
  }
  return { files: [...files].map((f) => f.slice(SRC.length + 1)), packages }
}

describe('dashboard shell static imports', () => {
  const closure = staticClosure()

  it.each([
    'components/step-up-dialog.tsx',
    'components/security/step-up-dialog.tsx',
    'components/security/totp-qr-code.tsx',
    'components/command-menu.tsx',
    'components/layout/about-dialog.tsx',
    'components/layout/keyboard-shortcuts-dialog.tsx',
    'components/layout/org-card.tsx',
    'lib/permissions/index.ts',
    'lib/permissions/can-mutate.ts',
    'config/api-route-permissions.json',
    'features/organization/api/use-members.ts',
    'components/layout/assets-quick-views.tsx',
    'features/account/components/account-shell.tsx',
  ])('%s loads on use, not with every page', (file) => {
    expect(closure.files).not.toContain(file)
  })

  it.each(['uqr', 'cmdk', 'vaul', 'recharts', 'date-fns', '@tanstack/react-table'])(
    'the %s package stays out of the shell',
    (pkg) => {
      expect(closure.packages.has(pkg)).toBe(false)
    }
  )
})
