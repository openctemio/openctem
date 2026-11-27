/**
 * Guard for the touch focus rule (`components/ui/touch-focus.ts`): on a touch
 * screen a popup never opens the keyboard by focusing a text field, except
 * on the typing surfaces listed in `TOUCH_TYPING_SURFACES`.
 *
 * The kit enforces it for kit fields (`Input`, `Textarea`, `CommandInput`,
 * and what is built on them) and for the focus trap of every kit surface.
 * Three things would bypass it, so each is listed here and a new one fails:
 *
 *  - a surface that opts out with `typingSurface` (each one a reviewed
 *    exception);
 *  - `autoFocus` on a raw `<input>` / `<textarea>` (not a kit field);
 *  - a `.focus()` call inside an `onOpenAutoFocus` handler.
 */
import fs from 'node:fs'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

const SRC_ROOT = path.resolve(__dirname, '../../..')

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'node_modules') continue
      sourceFiles(full, out)
    } else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out
}

const files = sourceFiles(SRC_ROOT).map((f) => ({
  rel: path.relative(SRC_ROOT, f).split(path.sep).join('/'),
  text: fs.readFileSync(f, 'utf8'),
}))

/** Surfaces that keep focusing their field on a touch screen (file: surface ids). */
const TYPING_SURFACE_SITES: Record<string, string[]> = {
  // The kit default of every command palette.
  'components/ui/command.tsx': ['command-menu'],
  // Password, code or reason that confirms a sensitive action.
  'components/security/step-up-dialog.tsx': ['step-up'],
  // Typing the name to confirm a destructive action.
  'components/confirm-dialog.tsx': ['type-to-confirm'],
  // The new name of a cloned workflow: the dialog's only field.
  'app/(dashboard)/(discovery)/scans/workflows/page.tsx': ['single-field'],
  // Add label: the popover's only field.
  'features/assets/components/service-cells/label-chips.tsx': ['single-field'],
}

/** Raw fields with `autoFocus`, none inside a popup on a touch screen. */
const RAW_AUTOFOCUS: Record<string, string> = {
  // The kit fields themselves: they pass on what useSurfaceAutoFocus allows.
  'components/ui/input.tsx': 'kit field, applies the rule',
  'components/ui/textarea.tsx': 'kit field, applies the rule',
  // The code boxes of sign-in and the step-up dialog (a typing surface).
  'components/security/verification-code-input.tsx': 'code entry, step-up or a page',
  // The editor of an inline markdown field; passes its own prop through.
  'components/ui/markdown-editor.tsx': 'inline editor, prop passthrough',
  // Target chips in the new-scan page (not a popup).
  'features/scans/components/new-scan/target-chips-field.tsx': 'inline page field',
}

/** `onOpenAutoFocus` handlers that move focus themselves. */
const OPEN_FOCUS_HANDLERS: Record<string, string> = {
  'components/confirm-dialog.tsx': 'typed confirmation (a typing surface)',
  'features/shared/components/responsive-popover.tsx': 'asks opensWithTextFocus() first',
  'components/ui/action-sheet.tsx': 'focuses a row, never a field',
  'components/ui/sidebar.tsx': 'focuses the current link, never a field',
  'components/graph-page/graph-page.tsx':
    "focuses the node's action (a link or button), never a field",
  'components/ui/modal-layout.tsx': 'the kit rule itself',
  'features/findings/components/bulk-dismiss-dialog.tsx':
    'focuses the reason picker (a select button), never a text field',
}

describe('touch focus guard', () => {
  it('every typing surface is a reviewed exception', () => {
    const found: Record<string, string[]> = {}
    for (const { rel, text } of files) {
      if (rel === 'components/ui/touch-focus.ts') continue
      const ids: string[] = []
      // typingSurface="id", typingSurface={cond ? 'id' : undefined}, or a
      // default parameter typingSurface = 'id'.
      for (const m of text.matchAll(/typingSurface(?:="([a-z-]+)"|=\{([^}]*)\}| = '([a-z-]+)')/g)) {
        if (m[1]) ids.push(m[1])
        if (m[3]) ids.push(m[3])
        if (m[2]) for (const q of m[2].matchAll(/'([a-z-]+)'/g)) ids.push(q[1])
      }
      if (ids.length) found[rel] = ids
    }
    expect(found).toEqual(TYPING_SURFACE_SITES)
  })

  it('autoFocus sits only on kit fields (which follow the rule), or on a listed raw field', () => {
    const raw: string[] = []
    for (const { rel, text } of files) {
      for (const m of text.matchAll(/\bautoFocus\b(?=\s*(?:=|\n|\s*\/?>|\s+[a-zA-Z]))/g)) {
        const before = text.slice(0, m.index)
        const open = before.lastIndexOf('<')
        const tag = /^<([A-Za-z][\w.]*)/.exec(before.slice(open))?.[1]
        if (tag && /^[a-z]/.test(tag) && (tag === 'input' || tag === 'textarea')) {
          if (!(rel in RAW_AUTOFOCUS)) raw.push(`${rel}: <${tag} autoFocus>`)
        }
      }
    }
    expect(raw).toEqual([])
  })

  it('no onOpenAutoFocus handler focuses a field behind the rule', () => {
    const unlisted: string[] = []
    for (const { rel, text } of files) {
      for (const m of text.matchAll(/onOpenAutoFocus=\{/g)) {
        const handler = text.slice(m.index, m.index + 600)
        if (/\.focus\(/.test(handler) && !(rel in OPEN_FOCUS_HANDLERS)) unlisted.push(rel)
      }
    }
    expect(unlisted).toEqual([])
  })
})
