/**
 * Guard: a component that fires a destructive mutation asks first or offers Undo.
 *
 * research/213 sorts every data-changing action into tiers: a reversible change
 * to one item gets an Undo toast (`undoToast`), anything else gets a
 * `ConfirmDialog` (typed text when it cannot be undone), and the server adds
 * step-up where it matters. This test parses every .tsx file of the tenant app
 * and the console and finds calls whose name says they take something away
 * (delete, remove, revoke, purge, reset, erase, rotate, regenerate, wipe,
 * destroy, disable, deactivate, suspend, cancel, a DELETE request). A file
 * with such a call must also use one of the protections below, or be listed in
 * REVIEWED with the reason it needs none (for example: it only edits a form
 * that is saved later, or its caller owns the dialog).
 *
 * The check is per file, so it cannot prove that the dialog guards that very
 * call; review does that. It catches the common regression: a new delete
 * button wired straight to the API.
 */
import fs from 'node:fs'
import path from 'node:path'

import ts from 'typescript'
import { describe, expect, it } from 'vitest'

const WEB_ROOT = path.resolve(__dirname, '../../..')
const ROOTS = ['src', 'console/src']

/** Verbs that take something away. Matched at the start of a call's name. */
const DESTRUCTIVE =
  /^(?:use)?(?:Bulk|bulk)?(?:delete|remove|revoke|purge|reset|erase|rotate|regenerate|wipe|destroy|disable|deactivate|suspend|cancel|unlink|detach|offboard)(?:[A-Z]\w*)?$/i

/** Names that match DESTRUCTIVE but change nothing on the server. */
const NOT_MUTATIONS = new Set([
  'removeEventListener',
  'removeItem', // localStorage / sessionStorage
  'removeChild',
  'removeAttribute',
  'removeProperty',
  'resetField', // react-hook-form
  'reset', // form.reset()
  'resetForm',
  'resetFilters',
  'resetState',
  'resetErrorBoundary',
  'cancelAnimationFrame',
  'cancelIdleCallback',
  'delete', // Map / Set / URLSearchParams .delete
  'deleteProperty',
  'removeFilter',
  'removeTag',
  'removeRow',
  'removeField',
  'removeCondition',
  'removeRule',
  'remove', // useFieldArray().remove
  'revokeObjectURL', // URL.revokeObjectURL after a download
  'resetPage', // pagination
  'resetListPage',
  'removeCookie',
  'removeStoredPermissions',
  'destroyWebSocketClient',
  // Draft edits inside a form or wizard that a later Save sends.
  'removeLabel',
  'removeArrayItem',
  'removeAt',
  'removeStep',
  'removeRecipient',
  'removeTargets',
  'removeKey',
  'resetKey',
  'resetLabelKey',
  'resetValues',
  'deactivatePreset', // a saved filter preset in this browser
])

/** Identifiers that show the file confirms or offers Undo. */
const PROTECTIONS = [
  /^ConfirmDialog$/,
  /^AdminConfirmDialog$/,
  /^AlertDialog$/,
  /^undoToast$/,
  // The confirmation that also asks for the authenticator code or password.
  /^StepUpDialog$/,
  // Feature dialogs that wrap ConfirmDialog for one object kind.
  /^\w*(?:Delete|Remove|Revoke|Confirm|Purge|Rotate|Regenerate|Offboard|Erase|Disable|Cancel)\w*Dialog\w*$/,
]

/**
 * Reviewed files, keyed by path relative to web/. Each entry says why the
 * file needs no dialog (the action is reversible or only edits a draft that a
 * later Save sends, or a sign-in step), or, prefixed "Gap:", names a known
 * missing confirmation that research/213 (audit 2026-10-24) schedules; remove
 * a "Gap:" entry when its fix lands.
 */
const REVIEWED: Record<string, string> = {
  'src/features/scans/components/new-scan/targets-step.tsx':
    'removeTyped drops a chip from the unsaved targets field of the new-scan form; the scan is created later.',
  'src/features/scope/components/scope-entry-dialog.tsx':
    'removeScopeValue and removeInvalidScopeValues only edit the pasted list in the dialog; nothing is sent until Add.',
  'src/features/findings/components/triage/triage-mode.tsx':
    'cancelApproval runs only from Undo (u), which reverses the request the person just sent in this session; the request is cancelled, not deleted.',
  'src/app/(dashboard)/(discovery)/scans/workflows/page.tsx':
    'Deactivating a workflow is reversible and stops work; only turning one on is confirmed.',
  'src/app/(dashboard)/settings/pentest/page.tsx':
    'Removes a row from the settings form; the save bar sends it.',
  'src/features/asset-groups/components/create-group/add-assets-step.tsx':
    'Removes an asset typed into the create-group wizard before it is saved.',
  'src/features/attack-surface/components/easm-review-queue.tsx':
    'The DELETE is the Undo of adding scope entries from the review queue.',
  'src/features/auth/components/mfa-step.tsx': 'Cancels the sign-in step, nothing is stored.',
  'src/features/auth/components/password-token-form.tsx':
    'The password reset form submit; the reset link is the confirmation.',
  'src/features/auth/components/pending-deletion-dialog.tsx':
    'Cancels a scheduled organization deletion: it keeps data, never removes any.',
  'src/features/business-services/components/business-service-assets.tsx':
    'Gap: unlinking an asset from a business service has no confirmation.',
  'src/features/business-units/components/business-unit-assets.tsx':
    'Gap: removing an asset from a business unit has no confirmation.',
  'src/features/content-catalog/components/requests-tab.tsx':
    'Withdraws your own install request; it can be asked again.',
  'src/features/findings/components/approval-policy-form.tsx':
    'Cancels a pending loosening of the approval policy: keeps the stricter policy.',
  'src/features/findings/components/finding-approval-settings-form.tsx':
    'Cancels a pending loosening of the approval settings: keeps the stricter settings.',
  'src/features/findings/components/detail/finding-approval-band.tsx':
    'Gap: cancelling an approval request from the finding has no confirmation (the approvals page asks).',
  'src/features/integrations/components/jira-webhook-dialog.tsx':
    'Gap: generating a new Jira webhook secret has no confirmation (server asks for step-up).',
  'src/features/scans/components/approval/scan-approvals-inbox.tsx':
    'Withdraws your own scan request; it can be asked again.',
  'src/features/secret-store/components/edit-credential-dialog.tsx':
    'Gap: rotating a stored secret saves from the edit form with no confirmation (server asks for step-up).',
  'src/features/sensors/components/sensor-tool-settings.tsx':
    'Gap: resetting a sensor tool override to the organization default has no confirmation.',
  'src/features/shared/components/watchers-block.tsx':
    'Removing a watcher is reversible (being replaced by the watchers sheet with Undo).',
  'src/features/workflows/components/automation-canvas.tsx':
    'Removes a node from the local canvas draft; publishing saves it.',
  'console/src/features/admin-console/components/instance-scan-zones-card.tsx':
    'Gap: Delete sits in the edit form behind the reason and code, with no separate confirmation.',
}

function sourceFiles(): string[] {
  const out: string[] = []
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '__tests__' || entry.name === 'ui')
          continue
        walk(full)
      } else if (
        entry.name.endsWith('.tsx') &&
        !entry.name.endsWith('.test.tsx') &&
        !entry.name.endsWith('.stories.tsx')
      ) {
        out.push(full)
      }
    }
  }
  for (const root of ROOTS) {
    const dir = path.join(WEB_ROOT, root)
    if (fs.existsSync(dir)) walk(dir)
  }
  return out
}

function calleeName(expr: ts.Expression): string | undefined {
  if (ts.isIdentifier(expr)) return expr.text
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text
  return undefined
}

interface Scan {
  destructive: string[]
  protected: boolean
}

export function scanSource(file: string, text: string): Scan {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const destructive = new Set<string>()
  let isProtected = false
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node.expression)
      if (name && DESTRUCTIVE.test(name) && !NOT_MUTATIONS.has(name)) destructive.add(name)
      // api.del(...) and fetch(..., { method: 'DELETE' })
      if (name === 'del') destructive.add('del')
    }
    if (
      ts.isPropertyAssignment(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'method' &&
      ts.isStringLiteralLike(node.initializer) &&
      node.initializer.text.toUpperCase() === 'DELETE'
    ) {
      destructive.add("method: 'DELETE'")
    }
    if (ts.isIdentifier(node) && PROTECTIONS.some((re) => re.test(node.text))) {
      isProtected = true
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return { destructive: [...destructive].sort(), protected: isProtected }
}

describe('destructive actions ask first or offer Undo', () => {
  const files = sourceFiles()

  it('finds the source files', () => {
    expect(files.length).toBeGreaterThan(100)
  })

  it('every component with a destructive call uses ConfirmDialog, undoToast or a reviewed reason', () => {
    const offenders: string[] = []
    for (const file of files) {
      const rel = path.relative(WEB_ROOT, file).split(path.sep).join('/')
      const scan = scanSource(rel, fs.readFileSync(file, 'utf8'))
      if (scan.destructive.length === 0 || scan.protected || rel in REVIEWED) continue
      offenders.push(`${rel}: ${scan.destructive.join(', ')}`)
    }
    expect(
      offenders,
      'Add a ConfirmDialog (research/213 tier T1+) or undoToast (T0), or list the file in REVIEWED with the reason'
    ).toEqual([])
  }, 120_000) // parses every .tsx file

  it('has no stale REVIEWED entries', () => {
    const stale: string[] = []
    for (const rel of Object.keys(REVIEWED)) {
      const full = path.join(WEB_ROOT, rel)
      // A file another change removed is skipped, so deleting a file never
      // breaks this test; tidy the entry when you see it.
      if (!fs.existsSync(full)) continue
      // Only a file with no destructive call left is stale. A file that gained
      // a dialog in another change keeps its entry until someone tidies it, so
      // merge order never breaks this test.
      const scan = scanSource(rel, fs.readFileSync(full, 'utf8'))
      if (scan.destructive.length === 0) stale.push(`${rel}: has no destructive call any more`)
    }
    expect(stale).toEqual([])
  }, 60_000)

  it('flags a delete wired straight to the API', () => {
    const scan = scanSource(
      'x.tsx',
      `export function X() { const del = useDeleteWidget(); return <button onClick={() => del.trigger()}>x</button> }`
    )
    expect(scan.destructive).toEqual(['useDeleteWidget'])
    expect(scan.protected).toBe(false)
  })

  it('accepts a delete behind ConfirmDialog or undoToast', () => {
    expect(
      scanSource('x.tsx', `const d = useDeleteWidget(); <ConfirmDialog handleConfirm={d} />`)
        .protected
    ).toBe(true)
    expect(
      scanSource('x.tsx', `await revokeKey(id); undoToast({ message: 'x', undo, t })`).protected
    ).toBe(true)
  })

  it('ignores calls that change nothing on the server', () => {
    const scan = scanSource(
      'x.tsx',
      `window.removeEventListener('x', f); form.reset(); params.delete('q'); localStorage.removeItem('k')`
    )
    expect(scan.destructive).toEqual([])
  })
})
