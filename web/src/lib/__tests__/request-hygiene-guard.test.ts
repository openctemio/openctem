/**
 * Guard: client data fetching goes through the shared API layer, one cache
 * key per URL, and every polling site is reviewed.
 *
 * research/81 (the page-load request budget) found that most redundant
 * requests came from three habits, each of which this test now counts:
 *
 *  1. RAW_FETCH: `fetch('/api/v1/...')` from a component or hook. It skips the
 *     shared client (`@/lib/api/client`: in-flight de-duplication, CSRF,
 *     token refresh, error mapping) and SWR's cache, so nothing else on the
 *     page can reuse the answer.
 *  2. TUPLE_KEY: an SWR key like `['/api/v1/x', tenantId]` or an opaque label
 *     like `['asset', id]`. SWR caches by key, so the same URL under
 *     `'/api/v1/x'` elsewhere is a second request and a second copy that
 *     `mutate('/api/v1/x')` never reaches. Key by the URL string: a tenant
 *     switch drops every cached answer (tenant-provider, clearSwrCache).
 *  3. POLLING: `refreshInterval`. A page that polls what the WebSocket already
 *     pushes, or polls while hidden UI is closed, multiplies requests. New
 *     polling needs a reviewer to agree it cannot be an event.
 *
 * Each count is a ratchet. A file may not gain occurrences, and when a file
 * loses some, its entry below must be lowered (or removed) in the same change,
 * so the lists only ever shrink.
 */
import fs from 'node:fs'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')

/** Where raw fetch is the implementation, not a bypass of it. */
const RAW_FETCH_EXEMPT_DIRS = ['lib/api/', 'app/api/']

/** Reviewed raw `fetch('/api/v1/…')` call sites, file → count. */
const RAW_FETCH_BASELINE: Record<string, number> = {
  'features/repositories/components/repository-workspace.tsx': 1,
  'context/tenant-provider.tsx': 1,
  'features/findings/components/detail/evidence-tab.tsx': 1,
  'features/pentest/components/attachment-upload.tsx': 2,
  'features/pentest/components/report-builder.tsx': 1,
  'features/scanner-templates/components/scanner-templates-section.tsx': 1,
  'features/tenant/components/create-team-form.tsx': 1,
  'stores/auth-store.ts': 1,
}

/** Reviewed `['/api/v1/…', …]` SWR keys, file → count. */
const TUPLE_KEY_BASELINE: Record<string, number> = {
  'features/assets/hooks/use-asset-tags.ts': 1,
  'features/assets/hooks/use-assets.ts': 2,
  'features/exposures/hooks/use-exposures.ts': 2,
  'features/scan-zones/components/zone-coverage-card.tsx': 1,
  'features/scans/components/new-scan/workflow-preview.tsx': 1,
  'features/threat-intel/hooks/use-threat-intel.ts': 7,
  'hooks/use-build-versions.ts': 2,
}

/** Reviewed `refreshInterval` options, file → count. */
const POLLING_BASELINE: Record<string, number> = {
  'app/(dashboard)/(discovery)/scans/[id]/page.tsx': 2,
  'app/(dashboard)/notifications/page.tsx': 1,
  'features/ai-triage/hooks/use-ai-triage.ts': 1,
  'features/ci-runners/api/use-ci.ts': 2,
  'features/findings/api/use-finding-retests.ts': 1,
  'features/findings/api/use-findings-api.ts': 1,
  'features/notifications/api/use-notification-api.ts': 1,
  'features/scan-freeze/api/use-freeze-windows.ts': 1,
  'features/scans/components/run-detail-sheet.tsx': 1,
  // The run list and its counts poll on their own clocks: fast only while a
  // listed run is live (research/81); it was one shared 30 s poll before.
  'features/scans/components/scan-runs-tab.tsx': 2,
  'features/sensors/components/sensor-detail-sheet.tsx': 1,
  'features/sensors/components/sensor-install-flow.tsx': 1,
  'lib/api/hooks.ts': 1,
  'lib/api/scan-workflow-hooks.ts': 1,
  'lib/api/security-hooks.ts': 1,
  'lib/api/sensor-hooks.ts': 6,
  'lib/api/sensor-pairing-hooks.ts': 1,
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '__tests__' || entry.name === 'generated')
        continue
      walk(full, out)
    } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.(test|spec)\.(ts|tsx)$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

/** The literal text a string or template literal starts with, if any. */
function literalPrefix(node: ts.Node | undefined): string | null {
  if (!node) return null
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text
  if (ts.isTemplateExpression(node)) return node.head.text
  return null
}

const SWR_HOOKS = new Set(['useSWR', 'useSWRImmutable', 'useSWRInfinite'])

/** A tuple element that partitions a key by tenant. */
const TENANT_IDENT = /^(tid|tenantId|currentTenantId|tenantID)$/

/** `x as T`, `x!` and `(x)` → `x`. */
function unwrap(node: ts.Expression): ts.Expression {
  while (
    ts.isAsExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isParenthesizedExpression(node)
  )
    node = node.expression
  return node
}

function isSwrCall(node: ts.CallExpression): boolean {
  return ts.isIdentifier(node.expression) && SWR_HOOKS.has(node.expression.text)
}

interface Counts {
  rawFetch: Record<string, number>
  tupleKey: Record<string, number>
  polling: Record<string, number>
}

function scan(): Counts {
  const counts: Counts = { rawFetch: {}, tupleKey: {}, polling: {} }
  const bump = (m: Record<string, number>, f: string) => (m[f] = (m[f] ?? 0) + 1)

  for (const file of walk(SRC_ROOT)) {
    const rel = path.relative(SRC_ROOT, file).split(path.sep).join('/')
    const text = fs.readFileSync(file, 'utf8')
    if (!/fetch\(|useSWR|refreshInterval/.test(text)) continue
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true)
    const rawFetchExempt = RAW_FETCH_EXEMPT_DIRS.some((d) => rel.startsWith(d))
    const usesSwr = text.includes('useSWR')

    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
        const name = node.expression.text
        if (name === 'fetch' && !rawFetchExempt) {
          const prefix = literalPrefix(node.arguments[0])
          if (prefix !== null && prefix.startsWith('/api/')) bump(counts.rawFetch, rel)
        }
        if (SWR_HOOKS.has(name)) {
          let key = node.arguments[0]
          // `cond ? key : null` — look at the key branch.
          if (key && ts.isConditionalExpression(key)) key = key.whenTrue
          if (key && ts.isArrayLiteralExpression(key)) key = unwrap(key)
          if (key && ts.isArrayLiteralExpression(key)) {
            const first = key.elements[0]
            const isUrlConst =
              first !== undefined && ts.isIdentifier(first) && /_URL$|Url$/.test(first.text)
            // Any string as the first element: a URL (`['/api/v1/x', tid]`)
            // or an opaque label (`['asset', id]`), never shared with the
            // URL-keyed readers of the same endpoint.
            if (literalPrefix(first) !== null || isUrlConst) bump(counts.tupleKey, rel)
          }
        }
      }
      // A key builder that returns `[url, tenantId]` (the same tuple, one level
      // removed from the useSWR call).
      if (
        usesSwr &&
        ts.isArrayLiteralExpression(node) &&
        node.elements.length >= 2 &&
        !(node.parent && ts.isCallExpression(node.parent) && isSwrCall(node.parent)) &&
        node.elements.slice(1).some((e) => {
          const u = unwrap(e)
          if (ts.isIdentifier(u)) return TENANT_IDENT.test(u.text)
          // currentTenant.id / currentTenant?.id
          return (
            ts.isPropertyAccessExpression(u) &&
            u.name.text === 'id' &&
            /tenant/i.test(u.expression.getText())
          )
        }) &&
        (ts.isIdentifier(unwrap(node.elements[0])) ||
          (literalPrefix(node.elements[0]) ?? '').startsWith('/api/'))
      ) {
        bump(counts.tupleKey, rel)
      }
      if (
        ts.isPropertyAssignment(node) &&
        ts.isIdentifier(node.name) &&
        node.name.text === 'refreshInterval' &&
        !(ts.isNumericLiteral(node.initializer) && node.initializer.text === '0')
      ) {
        bump(counts.polling, rel)
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }
  return counts
}

function ratchet(name: string, found: Record<string, number>, baseline: Record<string, number>) {
  const problems: string[] = []
  for (const [file, n] of Object.entries(found)) {
    const allowed = baseline[file] ?? 0
    if (n > allowed) problems.push(`${name}: ${file} has ${n} (reviewed: ${allowed})`)
  }
  for (const [file, allowed] of Object.entries(baseline)) {
    const n = found[file] ?? 0
    if (n < allowed)
      problems.push(`${name}: ${file} now has ${n}; lower its baseline entry from ${allowed}`)
  }
  return problems
}

describe('request hygiene guard', () => {
  const counts = scan()

  it('no new raw fetch of /api/ outside the API layer', () => {
    expect(ratchet('RAW_FETCH', counts.rawFetch, RAW_FETCH_BASELINE)).toEqual([])
  })

  it('no new [url, …] tuple SWR keys (key by the URL string)', () => {
    expect(ratchet('TUPLE_KEY', counts.tupleKey, TUPLE_KEY_BASELINE)).toEqual([])
  })

  it('no unreviewed polling (refreshInterval)', () => {
    expect(ratchet('POLLING', counts.polling, POLLING_BASELINE)).toEqual([])
  })
})
