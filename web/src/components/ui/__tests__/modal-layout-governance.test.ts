/**
 * Governance: every modal surface uses the shared frame of
 * components/ui/modal-layout.tsx — a fixed header, a body that is the only
 * scroll container, a fixed footer. Dialogs used to put `max-h-[90vh]
 * overflow-y-auto` on the whole content, so the title, the close button and
 * the actions scrolled away with the fields (worst on a phone). This test
 * fails when:
 *
 *   - a DialogContent / AlertDialogContent / SheetContent sets its own scroll
 *     or layout (`overflow-*`, `max-h-*`, `flex`, `grid`, `p-0`, `gap-*`), or a
 *     DialogContent / AlertDialogContent its own width (`max-w-*`: use `size`);
 *   - a file renders DialogContent without DialogHeader + DialogBody, or
 *     SheetContent without SheetHeader + SheetBody, or AlertDialogContent
 *     without AlertDialogHeader + AlertDialogFooter.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = join(__dirname, '../../..')

/** Surfaces with their own, reviewed frame. Never add a form dialog here. */
const EXEMPT = new Set([
  // The command palette: a search field and a list, no header or footer.
  'components/ui/command.tsx',
  // The mobile sidebar is a navigation drawer, not a modal with actions.
  'components/ui/sidebar.tsx',
  // The entity detail drawer frame (pinned header, scrolling body, footer
  // portal) shared by every detail sheet.
  'features/shared/components/detail-sheet-layout.tsx',
])

/**
 * Files not migrated yet. Remove an entry when its dialogs use the frame
 * (the test fails while a listed file is already clean); never add one.
 */
const PENDING = new Set<string>([
  'app/(dashboard)/(discovery)/assets/groups/page.tsx',
  'app/(dashboard)/(discovery)/components/ecosystems/page.tsx',
  'app/(dashboard)/(discovery)/scans/workflows/page.tsx',
  'app/(dashboard)/findings/approvals/page.tsx',
  'app/(dashboard)/(mobilization)/automations/page.tsx',
  'app/(dashboard)/(mobilization)/exceptions/page.tsx',
  'app/(dashboard)/(mobilization)/remediation/page.tsx',
  'app/(dashboard)/(prioritization)/priority-rules/dry-run-dialog.tsx',
  'app/(dashboard)/(prioritization)/priority-rules/page.tsx',
  'app/(dashboard)/(scoping)/attacker-profiles/page.tsx',
  'app/(dashboard)/(scoping)/attack-surface/external/page.tsx',
  'app/(dashboard)/(scoping)/business-services/page.tsx',
  'app/(dashboard)/(scoping)/business-units/page.tsx',
  'app/(dashboard)/(scoping)/compliance/page.tsx',
  'app/(dashboard)/(scoping)/crown-jewels/page.tsx',
  'app/(dashboard)/(scoping)/cycles/page.tsx',
  'app/(dashboard)/settings/api-keys/page.tsx',
  'app/(dashboard)/settings/integrations/siem/page.tsx',
  'app/(dashboard)/settings/integrations/ticketing/page.tsx',
  'app/(dashboard)/settings/mcp/page.tsx',
  'app/(dashboard)/settings/members/page.tsx',
  'app/(dashboard)/settings/modules/page.tsx',
  'app/(dashboard)/settings/roles/page.tsx',
  'app/(dashboard)/settings/scim/page.tsx',
  'app/(dashboard)/(validation)/controls/page.tsx',
  'app/(dashboard)/(validation)/control-testing/page.tsx',
  'app/(dashboard)/(validation)/pentest/campaigns/page.tsx',
  'app/(dashboard)/(validation)/pentest/findings/new/page.tsx',
  'components/layout/about-dialog.tsx',
  'components/layout/keyboard-shortcuts-dialog.tsx',
  'components/step-up-dialog.tsx',
  'features/access-control/components/add-member-to-role-dialog.tsx',
  'features/access-control/components/assignment-rule-detail-sheet.tsx',
  'features/access-control/components/assignment-rules-section.tsx',
  'features/access-control/components/create-role-sheet.tsx',
  'features/access-control/components/edit-role-sheet.tsx',
  'features/access-control/components/group-detail-sheet/add-asset-dialog.tsx',
  'features/access-control/components/group-detail-sheet/add-member-dialog.tsx',
  'features/access-control/components/group-detail-sheet/bulk-add-assets-dialog.tsx',
  'features/access-control/components/group-detail-sheet/scope-rule-dialog.tsx',
  'features/access-control/components/group-detail-sheet/scope-rules-tab.tsx',
  'features/access-control/components/group-detail-sheet.tsx',
  'features/access-control/components/teams-section.tsx',
  'features/account/components/password-card.tsx',
  'features/account/components/two-factor-card.tsx',
  'features/admin-console/components/access-requests-panel.tsx',
  'features/admin-console/components/admin-confirm-dialog.tsx',
  'features/admin-console/components/create-admin-dialog.tsx',
  'features/admin-console/components/create-first-owner-dialog.tsx',
  'features/admin-console/components/create-organization-dialog.tsx',
  'features/admin-console/components/organization-plan-panel.tsx',
  'features/admin-console/components/target-mapping-dialog.tsx',
  'features/asset-groups/components/create-group/create-group-dialog.tsx',
  'features/asset-groups/components/edit-group/add-assets-dialog.tsx',
  'features/asset-groups/components/edit-group/edit-group-dialog.tsx',
  'features/asset-lifecycle/components/dry-run-dialog.tsx',
  'features/asset-lifecycle/components/lifecycle-snooze-menu.tsx',
  'features/assets/components/asset-form-dialog-shared.tsx',
  'features/assets/components/asset-owners-tab.tsx',
  'features/assets/components/asset-relationships-tab.tsx',
  'features/assets/components/inventory/inventory-bulk-bar.tsx',
  'features/assets/components/inventory/inventory-business-context-actions.tsx',
  'features/assets/components/link-assets-dialog.tsx',
  'features/assets/components/relationships/add-relationship-dialog.tsx',
  'features/attack-surface/components/easm-rule-dialog.tsx',
  'features/attack-surface/components/easm-verify-domain-dialog.tsx',
  'features/capabilities/components/create-capability-dialog.tsx',
  'features/capabilities/components/edit-capability-dialog.tsx',
  'features/ci-runners/components/ci-runs-view.tsx',
  'features/ci-runners/components/ci-trust-settings.tsx',
  'features/cycles/components/charter-editor-sheet.tsx',
  'features/cycles/components/cycle-detail-tabs.tsx',
  'features/exceptions/components/suppression-form-dialog.tsx',
  'features/exposures/components/exposure-state-actions.tsx',
  'features/findings/components/approval-dialog.tsx',
  'features/findings/components/create-ticket-dialog.tsx',
  'features/findings/components/detail/manual-evidence-notes.tsx',
  'features/findings/components/import-results-dialog.tsx',
  'features/findings/components/mark-duplicate-dialog.tsx',
  'features/findings/components/mark-fixed-dialog.tsx',
  'features/integrations/components/routing-rules-dialog.tsx',
  'features/integrations/components/scanners/tenable-connector-dialog.tsx',
  'features/notifications/components/add-notification-dialog.tsx',
  'features/notifications/components/edit-notification-dialog.tsx',
  'features/organization/components/add-user-dialog.tsx',
  'features/organization/components/invite-user-dialog.tsx',
  'features/organization/components/member-access-dialog.tsx',
  'features/organization/components/offboard-member-dialog.tsx',
  'features/organization/components/setup-link-dialog.tsx',
  'features/organization/components/trusted-organizations.tsx',
  'features/pentest/components/campaign-detail-sheet.tsx',
  'features/pentest/components/finding-detail-sheet.tsx',
  'features/pentest/components/pentest-retests-section.tsx',
  'features/pentest/components/report-builder.tsx',
  'features/pentest/components/template-manager.tsx',
  'features/remediation/components/create-jira-epic-dialog.tsx',
  'features/remediation/components/link-findings-dialog.tsx',
  'features/remediation/components/resolve-campaign-dialog.tsx',
  'features/remediation-groups/components/create-campaign-from-group-dialog.tsx',
  'features/remediation-groups/components/resolve-group-dialog.tsx',
  'features/reports/components/new-schedule-dialog.tsx',
  'features/saved-views/components/saved-views-menu.tsx',
  'features/scan-freeze/components/freeze-window-dialog.tsx',
  'features/scan-freeze/components/zone-freeze-windows-dialog.tsx',
  'features/scanner-templates/components/add-scanner-template-dialog.tsx',
  'features/scan-profiles/components/add-preset-dialog.tsx',
  'features/scan-profiles/components/add-scan-profile-dialog.tsx',
  'features/scan-profiles/components/clone-scan-profile-dialog.tsx',
  'features/scan-profiles/components/edit-scan-profile-dialog.tsx',
  'features/scans/components/clone-scan-dialog.tsx',
  'features/scans/components/edit-scan-dialog.tsx',
  'features/scans/components/new-scan/new-scan-dialog.tsx',
  'features/scans/components/quick-scan-dialog.tsx',
  'features/scans/components/run-task-logs-dialog.tsx',
  'features/scans/components/scan-assets-dialog.tsx',
  'features/scans/hooks/use-scan-trigger.tsx',
  'features/scan-workflows/components/visual-builder-dialog.tsx',
  'features/scan-zones/components/scan-zone-dialog.tsx',
  'features/scan-zones/components/zone-sensors-dialog.tsx',
  'features/scm-connections/components/add-connection-dialog.tsx',
  'features/scm-connections/components/edit-connection-dialog.tsx',
  'features/scm-connections/components/sync-repositories-dialog.tsx',
  'features/scope/components/exclusion-testing-dialog.tsx',
  'features/scope/components/scope-entry-dialog.tsx',
  'features/scope/components/scope-entry-edit-dialog.tsx',
  'features/scope/components/scope-exclusion-dialog.tsx',
  'features/secret-store/components/add-credential-dialog.tsx',
  'features/secret-store/components/edit-credential-dialog.tsx',
  'features/sensors/components/edit-sensor-dialog.tsx',
  'features/sensors/components/install-sensor-dialog.tsx',
  'features/sensors/components/pair-sensor-dialog.tsx',
  'features/sensors/components/regenerate-key-dialog.tsx',
  'features/sensors/components/sensor-grant-edit-dialog.tsx',
  'features/sensors/components/sensors-section.tsx',
  'features/shared/components/filter-sheet.tsx',
  'features/shared/components/sheet-detail-toolbar.tsx',
  'features/shared/components/sheet-primitives.tsx',
  'features/sla/components/sla-policy-dialog.tsx',
  'features/template-sources/components/add-template-source-dialog.tsx',
  'features/template-sources/components/edit-template-source-dialog.tsx',
  'features/threat-intel/components/iocs-panel.tsx',
  'features/threat-intel/components/threat-actors-panel.tsx',
  'features/tools/components/add-tool-dialog.tsx',
  'features/verified-domains/components/add-domain-dialog.tsx',
  'features/verified-domains/components/domain-jit-dialog.tsx',
  'features/verified-domains/components/verified-domains-list.tsx',
  'features/web-surface/components/endpoint-sheet.tsx',
])

function* tsxFiles(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'node_modules' || name === '__tests__') continue
    if (statSync(p).isDirectory()) yield* tsxFiles(p)
    else if (name.endsWith('.tsx') && !name.endsWith('.test.tsx')) yield p
  }
}

const CONTENT_TAG = /<(DialogContent|AlertDialogContent|SheetContent)\b([\s\S]*?)>/g
// A class token, with any variant prefix (`sm:max-w-lg`).
const token = (body: string) =>
  new RegExp(`(?:^|[\\s'"\`])((?:[\\w-]+:)*(?:${body}))(?=$|[\\s'"\`])`)
const LAYOUT_CLASS = token(
  'overflow(?:-[xy])?-\\w+|max-h-[^\\s\'"`]+|flex|grid|p-0|gap-[^\\s\'"`]+'
)
const WIDTH_CLASS = token('max-w-[^\\s\'"`]+')

const REQUIRED: Record<string, string[]> = {
  DialogContent: ['<DialogHeader', '<DialogBody'],
  SheetContent: ['<SheetHeader', '<SheetBody'],
  AlertDialogContent: ['<AlertDialogHeader', '<AlertDialogFooter'],
}

/** What is wrong with one file's modal surfaces (empty: nothing). */
function problems(src: string): string[] {
  const out: string[] = []
  const surfaces = new Set<string>()
  for (const m of src.matchAll(CONTENT_TAG)) {
    const [, tag, attrs] = m
    surfaces.add(tag)
    const cls = attrs.match(/className=(?:"([^"]*)"|\{([\s\S]*?)\}\s*(?:\w+=|\/?$))/)
    const value = cls ? (cls[1] ?? cls[2] ?? '') : ''
    const layout = value.match(LAYOUT_CLASS)
    if (layout) out.push(`${tag} sets "${layout[1]}" (the frame owns scroll and layout)`)
    if (tag !== 'SheetContent') {
      const width = value.match(WIDTH_CLASS)
      if (width) out.push(`${tag} sets "${width[1]}" (use size="sm|md|lg|xl|full")`)
    }
  }
  for (const tag of surfaces) {
    for (const part of REQUIRED[tag]) {
      if (!src.includes(part)) out.push(`${tag} without ${part.slice(1)}`)
    }
  }
  return out
}

describe('modal surfaces', () => {
  const files = [...tsxFiles(SRC)].map((f) => ({
    rel: relative(SRC, f),
    src: readFileSync(f, 'utf8'),
  }))

  it('use the shared header / body / footer frame', () => {
    const offenders: string[] = []
    for (const { rel, src } of files) {
      if (EXEMPT.has(rel) || PENDING.has(rel)) continue
      if (rel.startsWith('components/ui/')) continue
      for (const p of problems(src)) offenders.push(`${rel}: ${p}`)
    }
    expect(offenders).toEqual([])
  })

  it('keep the pending list honest (remove a migrated file from it)', () => {
    const byPath = new Map(files.map((f) => [f.rel, f.src]))
    const stale = [...PENDING].filter((rel) => {
      const src = byPath.get(rel)
      return src === undefined || problems(src).length === 0
    })
    expect(stale).toEqual([])
  })

  it('catches the patterns it is meant to catch', () => {
    expect(
      problems(
        '<DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto"><DialogHeader/></DialogContent>'
      )
    ).toEqual([
      'DialogContent sets "max-h-[90vh]" (the frame owns scroll and layout)',
      'DialogContent sets "sm:max-w-lg" (use size="sm|md|lg|xl|full")',
      'DialogContent without DialogBody',
    ])
    expect(
      problems('<DialogContent size="lg"><DialogHeader/><DialogBody/></DialogContent>')
    ).toEqual([])
    expect(problems('<SheetContent className="w-full sm:max-w-xl">')).toEqual([
      'SheetContent without SheetHeader',
      'SheetContent without SheetBody',
    ])
    expect(problems('<SheetContent className="flex flex-col p-0">')[0]).toContain('"flex"')
  })
})
