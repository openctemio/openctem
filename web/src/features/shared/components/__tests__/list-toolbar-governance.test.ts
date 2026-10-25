/**
 * Governance: one list toolbar (research/267).
 *
 * Every list draws its toolbar through `ListToolbar` (directly, or through
 * `DataTable`, which renders it), and its search box through `ListSearch`.
 * Before this, 40-odd lists hand-built their own search field (each with its
 * own width, height, icon spacing and placeholder style) and the filter
 * trigger sat flush against the search on one page and 8px away on the next.
 *
 * Rules, over every .tsx file of the app and the admin console (tests
 * excluded):
 *
 *   1. No raw search field: an `<Input>` whose props say "search" (a
 *      placeholder or aria-label key/text with "search", or `type="search"`)
 *      is drawn only by list-search.tsx. A list passes `search` to
 *      `DataTable` / `ListToolbar`, or renders `ListSearch`. Pickers inside a
 *      dialog are listed in `RAW_SEARCH_ALLOWED` with the reason; that list
 *      can only shrink.
 *   2. The filter panel trigger (`FilterPanelToggle`) is drawn by ListToolbar
 *      from `filterToggle` (DataTable passes it on); pages do not place it
 *      themselves, so it always sits joined to the search.
 *   3. Joining the trigger to the search is ListSearch's job: no other file
 *      squares off the trigger's corners (`[data-slot=filter-button]` with
 *      `rounded-e-none`).
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const WEB = join(__dirname, '..', '..', '..', '..', '..')
const ROOTS = [join(WEB, 'src'), join(WEB, 'console', 'src')]

function walk(path: string, out: string[]) {
  let st
  try {
    st = statSync(path)
  } catch {
    return
  }
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name === '__tests__' || name.startsWith('.')) continue
      walk(join(path, name), out)
    }
  } else if (path.endsWith('.tsx') && !/\.test\.tsx$/.test(path)) {
    out.push(path)
  }
}

const files: string[] = []
for (const root of ROOTS) walk(root, files)
const rel = (abs: string) => relative(WEB, abs).split(sep).join('/')

/**
 * Search fields that are not a list toolbar: a picker or lookup inside a
 * dialog, sheet or popover, sized to that surface. file -> reason.
 */
const RAW_SEARCH_ALLOWED: Record<string, string> = {
  'src/app/(dashboard)/(scoping)/crown-jewels/page.tsx':
    'asset picker in the add dialog (the list itself uses the DataTable search)',
  'src/features/assets/components/asset-sources-settings.tsx':
    'asset lookup for the policy preview',
  'src/features/assets/components/asset-access-grants-section.tsx':
    'member lookup inside the add-grant box',
  'src/app/(auth)/select-tenant/page.tsx':
    'organization chooser at sign-in, outside the console shell',
  'src/components/layout/org-card.tsx': 'organization switcher popover',
  'src/features/access-control/components/add-member-to-role-dialog.tsx':
    'member picker in a dialog',
  'src/features/access-control/components/create-role-sheet.tsx':
    'permission picker inside the role form',
  'src/features/access-control/components/edit-role-sheet.tsx':
    'permission picker inside the role form',
  'src/features/access-control/components/group-detail-sheet/add-asset-dialog.tsx':
    'asset picker in a dialog',
  'src/features/access-control/components/group-detail-sheet/bulk-add-assets-dialog.tsx':
    'asset picker in a dialog',
  'src/features/asset-groups/components/create-group/add-assets-step.tsx':
    'asset picker in a wizard step',
  'src/features/asset-groups/components/edit-group/add-assets-dialog.tsx':
    'asset picker in a dialog',
  'src/features/asset-groups/components/group-add-assets-dialog.tsx': 'asset picker in a dialog',
  'src/features/assets/components/inventory/inventory-facet-panel.tsx':
    'value search inside the filter panel',
  'src/features/assets/components/inventory/inventory-tags-facet.tsx':
    'value search inside the filter panel',
  'src/features/assets/components/inventory/inventory-technologies-facet.tsx':
    'value search inside the filter panel',
  'src/features/assets/components/link-assets-dialog.tsx': 'asset picker in a dialog',
  'src/features/assets/components/relationships/add-relationship-dialog.tsx':
    'asset picker in a dialog',
  'src/features/components/components/asset-chooser.tsx': 'asset picker popover',
  'src/features/components/components/dependency-graph.tsx':
    'finds a node in the graph canvas, not a list',
  'src/features/dashboards/components/dashboard-switcher.tsx': 'dashboard switcher popover',
  'src/features/dashboards/editor/widget-gallery.tsx': 'widget picker in the add-widget sheet',
  'src/features/findings/components/detail/retest-check-editor-dialog.tsx': 'picker in a dialog',
  'src/features/findings/components/mark-duplicate-dialog.tsx': 'finding picker in a dialog',
  'src/features/organization/components/personal-accounts-card.tsx':
    'member lookup field inside a form',
  'src/features/organization/components/team-picker.tsx': 'team picker',
  'src/features/pentest/components/campaign-create-wizard.tsx': 'picker in a wizard step',
  'src/features/pentest/components/campaign-detail-sheet.tsx': 'asset and member pickers in forms',
  'src/features/pentest/components/finding-editor/template-picker-dialog.tsx':
    'template picker in a dialog',
  'src/features/pentest/components/mark-duplicate-dialog.tsx': 'finding picker in a dialog',
  'src/features/pentest/components/report-template-reference.tsx':
    'variable lookup in the report editor',
  'src/features/remediation/components/add-tasks-dialog.tsx': 'task picker in a dialog',
  'src/features/remediation-hub/components/add-findings-to-task-dialog.tsx':
    'finding picker in a dialog',
  'src/features/scans/components/target-picker/asset-source.tsx':
    'target picker in the new-scan form',
  'src/features/scans/components/target-picker/group-source.tsx':
    'target picker in the new-scan form',
  'src/features/scan-workflows/components/node-palette.tsx': 'node palette in the workflow editor',
  'src/features/scm-connections/components/sync-repositories-dialog.tsx':
    'repository picker in a dialog',
  'src/features/shared/components/watchers/manage-watchers-dialog.tsx': 'member picker in a dialog',
  'src/features/ticket-mapping/components/field-mapper.tsx':
    'field lookup inside the mapping editor',
  'src/app/(dashboard)/findings/page.tsx':
    'deferred: migrates after the findings triage and hide-informational work lands',
}

/** Files that may render `FilterPanelToggle` / `FilterButton` themselves. file -> reason. */
const TRIGGER_ALLOWED: Record<string, string> = {
  'src/features/shared/components/filter-button.tsx': 'defines it',
  'src/features/shared/components/list-toolbar.tsx': 'renders filterToggle',
  'src/app/(dashboard)/findings/page.tsx':
    'deferred: migrates after the findings triage and hide-informational work lands',
}

/** Each `<Input ...>` element's props, up to its end. */
function inputBlocks(src: string): { line: number; props: string }[] {
  const out: { line: number; props: string }[] = []
  const re = /<Input(\s|$)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(src))) {
    let depth = 0
    let end = m.index
    for (let i = m.index; i < src.length && i < m.index + 3000; i++) {
      const c = src[i]
      if (c === '{') depth++
      else if (c === '}') depth--
      else if (c === '>' && depth === 0) {
        end = i
        break
      }
    }
    out.push({ line: src.slice(0, m.index).split('\n').length, props: src.slice(m.index, end) })
  }
  return out
}

const SEARCH_PROP =
  /(placeholder|aria-label)=\{?\s*(t\(\s*)?['"`][^'"`]*search[^'"`]*['"`]|type=["']search["']/i

describe('one list toolbar', () => {
  it('draws every search field through ListSearch (no raw search Input)', () => {
    const offenders: string[] = []
    for (const f of files) {
      const r = rel(f)
      if (r === 'src/features/shared/components/list-search.tsx' || RAW_SEARCH_ALLOWED[r]) continue
      for (const { line, props } of inputBlocks(readFileSync(f, 'utf8'))) {
        if (SEARCH_PROP.test(props)) offenders.push(`${r}:${line}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('keeps the raw-search allowlist honest (every entry still has a raw search field)', () => {
    const stale = Object.keys(RAW_SEARCH_ALLOWED).filter((r) => {
      const f = files.find((x) => rel(x) === r)
      if (!f) return true
      return !inputBlocks(readFileSync(f, 'utf8')).some(({ props }) => SEARCH_PROP.test(props))
    })
    expect(stale).toEqual([])
  })

  it('places the filter panel trigger only through DataTable filterToggle or ListToolbar filter', () => {
    const offenders: string[] = []
    for (const f of files) {
      const r = rel(f)
      if (TRIGGER_ALLOWED[r]) continue
      const src = readFileSync(f, 'utf8')
      if (/<FilterPanelToggle[\s>]/.test(src)) offenders.push(`${r}: FilterPanelToggle`)
      // A bare FilterButton is fine as the toolbar's `filter` (a sheet
      // trigger); anywhere else it is a trigger outside the toolbar.
      if (/<FilterButton[\s>]/.test(src) && !/\bfilter=\{/.test(src)) {
        offenders.push(`${r}: FilterButton outside ListToolbar filter`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('leaves joining the trigger to the search to ListSearch', () => {
    const offenders = files
      .filter((f) => rel(f) !== 'src/features/shared/components/list-search.tsx')
      // Deferred pages keep their own join until they move onto ListSearch.
      .filter((f) => !RAW_SEARCH_ALLOWED[rel(f)]?.startsWith('deferred'))
      .filter((f) => /\[data-slot=filter-button\]\]:rounded-e-none/.test(readFileSync(f, 'utf8')))
      .map(rel)
    expect(offenders).toEqual([])
  })

  it('writes every list search placeholder as "Search <fields>…" (one ellipsis character)', () => {
    const DICT = join(WEB, 'src', 'lib', 'i18n', 'dictionaries', 'en')
    const cache = new Map<string, Record<string, string>>()
    const en = (key: string): string | undefined => {
      const ns = key.split('.')[0]
      if (!cache.has(ns)) {
        try {
          cache.set(ns, JSON.parse(readFileSync(join(DICT, `${ns}.json`), 'utf8')))
        } catch {
          cache.set(ns, {})
        }
      }
      return cache.get(ns)![key]
    }
    const offenders: string[] = []
    const use = /(searchPlaceholder=\{t\(|placeholder:\s*t\()\s*'([\w.-]+)'(?:,\s*'([^']*)')?/g
    for (const f of files) {
      const r = rel(f)
      if (RAW_SEARCH_ALLOWED[r]) continue
      const src = readFileSync(f, 'utf8')
      // Only `placeholder:` inside a search object (`search={{` / `const search`).
      if (!/searchPlaceholder=|search=\{\{|const search\w* = \{|search: \{/.test(src)) continue
      for (const m of src.matchAll(use)) {
        const text = en(m[2]) ?? m[3]
        if (text && !text.endsWith('…')) offenders.push(`${r}: ${m[2]} "${text}"`)
      }
      // A literal placeholder is not translated.
      for (const m of src.matchAll(/searchPlaceholder="([^"]*)"/g))
        offenders.push(`${r}: literal "${m[1]}"`)
    }
    expect(offenders).toEqual([])
  })

  it('finds the files it checks', () => {
    const lists = files.filter((f) => /<DataTable[\s>]/.test(readFileSync(f, 'utf8')))
    expect(lists.length).toBeGreaterThan(80)
  })
})
