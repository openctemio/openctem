/**
 * Guard: label and value pairs use the shared components.
 *
 * A key-value grid written by hand (`<dl>` with its own `<dt>`/`<dd>` and
 * grid classes) is where long values broke out of their column: a sensor's
 * 40-character SDK pseudo-version was drawn over the next field (2026-10-25).
 * The shared components keep every value inside its column (`min-w-0`, words
 * wrap, tokens break anywhere) and give one look everywhere:
 *
 *   - `DetailFieldGrid` + `DetailField`: a drawer's fields, label above value
 *   - `KeyValueList`: label beside value (a details list, a dense row)
 *   - `MetaLine` + `MetaItem`: a line of short "label value" facts
 *
 * Only `features/shared/components` writes `<dt>`. The files listed below
 * predate this guard; take a file off the list when you migrate it, never add
 * one.
 */
import fs from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../..')

const NOT_YET_MIGRATED = new Set([
  'app/(dashboard)/insights/executive/page.tsx',
  'components/layout/about-dialog.tsx',
  'components/layout/org-card.tsx',
  'features/assets/components/asset-attribution-section.tsx',
  'features/assets/components/property-value.tsx',
  'features/assets/components/relationships/related-assets-list.tsx',
  'features/assets/components/technologies/technologies-by-category.tsx',
  'features/attack-surface/components/asset-web-evidence-card.tsx',
  'features/ci-runners/components/ci-runs-view.tsx',
  'features/ci-runners/components/ci-trust-preview.tsx',
  'features/dashboard/components/data-quality-view.tsx',
  'features/emerging-threats/components/emerging-threat-detail.tsx',
  'features/findings/components/approval-policy-form.tsx',
  'features/findings/components/detail/finding-evidence-items.tsx',
  'features/findings/components/detail/finding-fix-card.tsx',
  'features/findings/components/detail/finding-people.tsx',
  'features/findings/components/detail/finding-properties.tsx',
  'features/findings/components/detail/source-data-section.tsx',
  'features/findings/components/group-exceptions-panel.tsx',
  'features/findings/components/triage/triage-finding-view.tsx',
  'features/findings/components/triage/triage-keys-dialog.tsx',
  'features/import-mappings/components/preview-pane.tsx',
  'features/integrations/components/scanners/tenable-connector-card.tsx',
  'features/organization/components/dashboard-data-card.tsx',
  'features/pentest/components/finding-editor/finding-action-bar.tsx',
  'features/pentest/components/finding-editor/finding-summary-card.tsx',
  'features/pentest/components/template-editor/template-summary.tsx',
  'features/platform/components/platform-scanning-card.tsx',
  'features/programs/components/program-source.tsx',
  'features/remediation/components/campaign-detail.tsx',
  'features/remediation-hub/components/query-preview-panel.tsx',
  'features/remediation-hub/components/task-detail.tsx',
  'features/remediation-hub/components/task-people.tsx',
  'features/scans/components/new-scan/review-step.tsx',
  'features/scans/components/run-task-logs-dialog.tsx',
  'features/scan-zones/components/zone-routing-preview.tsx',
  'features/security-overview/components/security-overview.tsx',
  'features/sensors/components/edit-sensor-dialog.tsx',
  'features/sensors/components/pair-sensor-dialog.tsx',
  'features/threat-intel/components/threat-intel-stats.tsx',
  'features/vuln-matching/components/version-match-panel.tsx',
])

function tsxFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name)
    if (e.isDirectory())
      return e.name === 'node_modules' || e.name === '__tests__' ? [] : tsxFiles(p)
    return e.name.endsWith('.tsx') && !e.name.includes('.test.') ? [p] : []
  })
}

const writesDt = (rel: string) => /<dt[\s>]/.test(fs.readFileSync(path.join(SRC_ROOT, rel), 'utf8'))

describe('key-value lists', () => {
  const files = tsxFiles(SRC_ROOT).map((f) => path.relative(SRC_ROOT, f).split(path.sep).join('/'))

  it('use the shared components outside features/shared', () => {
    const offenders = files
      .filter((rel) => !rel.startsWith('features/shared/components/'))
      .filter((rel) => !NOT_YET_MIGRATED.has(rel))
      .filter(writesDt)
    expect(offenders).toEqual([])
  })

  it('lists only files that still need migrating', () => {
    const stale = [...NOT_YET_MIGRATED].filter((rel) => !files.includes(rel) || !writesDt(rel))
    expect(stale).toEqual([])
  })
})
