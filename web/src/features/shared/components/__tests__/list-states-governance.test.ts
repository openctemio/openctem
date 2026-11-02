import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * A list that cannot load must say so. A DataTable that is never given `error`
 * (or a custom `errorState`) renders a failed read as "nothing here". Every
 * file that renders a DataTable passes one of them, except the files below.
 * The list may only shrink: a listed file that now passes `error` fails here
 * until it is removed from the list.
 */
const ALLOW_LIST = [
  'src/app/(dashboard)/(discovery)/scans/workflows/page.tsx',
  'src/app/(dashboard)/settings/members/page.tsx',
  'src/app/(dashboard)/settings/roles/page.tsx',
  'src/features/access-control/components/assignment-rules-section.tsx',
  'src/features/access-control/components/teams-section.tsx',
  'src/features/assets/components/dedup-review-page.tsx',
  'src/features/assets/components/resolved-ports-section.tsx',
  'src/features/capabilities/components/capability-table.tsx',
  'src/features/credentials/components/credential-identity-groups.tsx',
  'src/features/findings/components/detail/related-tab.tsx',
  'src/features/findings/components/group-exceptions-panel.tsx',
  'src/features/my-work/components/finding-queue.tsx',
  'src/features/pentest/components/pentest-findings-section.tsx',
  'src/features/pentest/components/pentest-reports-section.tsx',
  'src/features/pentest/components/pentest-retests-section.tsx',
  'src/features/remediation-hub/components/my-tasks-queue.tsx',
  'src/features/reports/components/report-schedules-section.tsx',
  'src/features/scan-zones/components/scan-zone-table.tsx',
  'src/features/scope/components/scope-entries-table.tsx',
  'src/features/scope/components/scope-exclusions-table.tsx',
  'src/features/sensors/components/sensor-table.tsx',
  'src/features/threat-intel/components/detections-panel.tsx',
  'src/features/threat-intel/components/iocs-panel.tsx',
  'src/features/threat-intel/components/threat-actors-panel.tsx',
  'src/features/threat-model/components/threat-model-table.tsx',
  'src/features/tools/components/tool-table.tsx',
  'src/features/vulnerabilities/components/vulnerability-catalog-table.tsx',
]

const SRC = join(__dirname, '..', '..', '..', '..')

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name === 'node_modules' || name === '__tests__') continue
      walk(p, out)
    } else if (p.endsWith('.tsx') && !p.endsWith('.test.tsx')) {
      out.push(p)
    }
  }
  return out
}

const RENDERS_TABLE = /<DataTable(\s|>|$)/
const PASSES_ERROR = /\berror=|errorState=/

describe('list states governance', () => {
  const files = walk(SRC)
    .map((p) => ({ rel: relative(join(SRC, '..'), p).split(sep).join('/'), p }))
    .filter(({ p }) => RENDERS_TABLE.test(readFileSync(p, 'utf8')))

  it('every file that renders a DataTable passes error or errorState', () => {
    const missing = files
      .filter(
        ({ p, rel }) => !PASSES_ERROR.test(readFileSync(p, 'utf8')) && !ALLOW_LIST.includes(rel)
      )
      .map(({ rel }) => rel)
    expect(missing).toEqual([])
  })

  it('the allow list only shrinks', () => {
    const stale = ALLOW_LIST.filter((rel) => {
      const f = files.find((x) => x.rel === rel)
      return !f || PASSES_ERROR.test(readFileSync(f.p, 'utf8'))
    })
    expect(stale).toEqual([])
  })
})
