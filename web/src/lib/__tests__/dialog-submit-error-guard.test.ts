/**
 * A dialog or sheet shows why its submit failed in `<DialogSubmitError>`,
 * directly above the footer buttons. An error alert inside the scrolling body
 * sits above the fold when the person is at the bottom next to the submit
 * button: the action seems to do nothing (a refused scope entry showed no
 * message at all).
 *
 * The guard looks for a destructive `<Alert>` between a modal's content tag
 * and its footer tag, which is the scrolling body or the block above the
 * buttons:
 *
 * - a file that is not in dialog-submit-error-debt.json may have none;
 * - a listed file may not go above its count;
 * - a listed file that went below its count must lower it (or leave the
 *   list), so the debt only shrinks. Regenerate after a clean-up:
 *   UPDATE_DIALOG_ERROR_DEBT=1 npx vitest run src/lib/__tests__/dialog-submit-error-guard.test.ts
 *
 * A destructive alert that is not a submit error (a load failure of what the
 * dialog shows) is allowed with `submit-error-ok: <reason>` on the line of
 * the `<Alert` or the line above it.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import debt from './dialog-submit-error-debt.json'

const WEB = join(__dirname, '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')]
const DEBT_FILE = join(__dirname, 'dialog-submit-error-debt.json')
const SKIP_DIR = new Set(['__tests__', '__mocks__', 'generated', 'dictionaries', 'node_modules'])

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return SKIP_DIR.has(name) ? [] : sources(path)
    return name.endsWith('.tsx') && !/\.(test|spec|stories)\.tsx$/.test(name) ? [path] : []
  })
}

const CONTENT = /<(?:Dialog|AlertDialog|Sheet)Content\b/g
const FOOTER = /<(?:Dialog|AlertDialog|Sheet)Footer\b/
const DESTRUCTIVE_ALERT = /<Alert\b[^>]*variant="destructive"/g

/** Lines of destructive alerts that sit in a modal's body (see above). */
export function misplacedSubmitErrors(source: string): number[] {
  const lines = source.split('\n')
  const found: number[] = []
  for (const open of source.matchAll(CONTENT)) {
    const from = open.index ?? 0
    const rest = source.slice(from)
    const footer = rest.search(FOOTER)
    // A modal without a footer tag (a confirm dialog: the frame draws it) is
    // checked up to the next modal.
    const next = rest.slice(1).search(CONTENT)
    const end = footer >= 0 ? footer : next >= 0 ? next + 1 : rest.length
    const span = rest.slice(0, end)
    for (const alert of span.matchAll(DESTRUCTIVE_ALERT)) {
      const line = source.slice(0, from + (alert.index ?? 0)).split('\n').length
      const here = lines[line - 1] ?? ''
      const above = lines[line - 2] ?? ''
      if (here.includes('submit-error-ok') || above.includes('submit-error-ok')) continue
      if (!found.includes(line)) found.push(line)
    }
  }
  return found
}

function actual(): Record<string, number> {
  const out: Record<string, number> = {}
  for (const root of ROOTS)
    for (const file of sources(root)) {
      const n = misplacedSubmitErrors(readFileSync(file, 'utf8')).length
      if (n > 0) out[relative(WEB, file).split('\\').join('/')] = n
    }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1)))
}

describe('submit errors in dialogs', () => {
  it('flags a destructive alert in the body and accepts the shared component', () => {
    const bad = `<Dialog><DialogContent><DialogBody>
      {error && (
        <Alert variant="destructive"><AlertDescription>{error}</AlertDescription></Alert>
      )}
    </DialogBody><DialogFooter /></DialogContent></Dialog>`
    expect(misplacedSubmitErrors(bad)).toEqual([3])
    const good = `<Dialog><DialogContent><DialogBody>x</DialogBody>
      <DialogSubmitError message={error} />
      <DialogFooter /></DialogContent></Dialog>`
    expect(misplacedSubmitErrors(good)).toEqual([])
    const ok = `<DialogContent><DialogBody>
      {/* submit-error-ok: a load failure of what the dialog shows */}
      <Alert variant="destructive" />
    </DialogBody><DialogFooter /></DialogContent>`
    expect(misplacedSubmitErrors(ok)).toEqual([])
  })

  it('has no new destructive alert in a dialog body, and the debt only shrinks', () => {
    const now = actual()
    if (process.env.UPDATE_DIALOG_ERROR_DEBT) {
      writeFileSync(DEBT_FILE, JSON.stringify(now, null, 2) + '\n')
      return
    }
    const listed = debt as Record<string, number>
    const grew = Object.keys(now).filter((f) => now[f] > (listed[f] ?? 0))
    const shrank = Object.keys(listed).filter((f) => (now[f] ?? 0) < listed[f])
    expect(
      grew,
      'Show the submit error with <DialogSubmitError message={error} /> between the body and the footer (components/ui/dialog-submit-error.tsx).'
    ).toEqual([])
    expect(shrank, 'Fixed: lower the count in dialog-submit-error-debt.json').toEqual([])
  })
})
