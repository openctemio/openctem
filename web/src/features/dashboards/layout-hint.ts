/**
 * The offer shown on a person's copy of a template when the template has
 * changed since the copy was made: it gained widgets (add them, or switch to
 * a fresh copy), or its widgets were rearranged (switch to a fresh copy). The
 * old dashboard is always kept: stored dashboards are never changed on their
 * own; the person chooses. A dismissal is remembered per template version in
 * this browser (a per-viewer convenience).
 */

import type { Dashboard, DashboardWidget } from './api/dashboards.types'
import { templateByKey, type DashboardTemplate, type TemplateKey } from './templates'

/** Bump when a template offered here gains widgets, so the hint shows again. */
export const LAYOUT_HINT_VERSION = '6'
export const LAYOUT_HINT_DISMISSED_KEY = 'openctem:layout-hint-dismissed'

/** Templates whose copies are offered their new widgets, by widget id prefix. */
const OFFERED: ReadonlyArray<{ key: TemplateKey; prefix: string }> = [
  { key: 'overview', prefix: 'w_ov' },
  { key: 'ctem', prefix: 'w_ct' },
  { key: 'executive', prefix: 'w_ex' },
  { key: 'program', prefix: 'w_pr' },
  { key: 'triage', prefix: 'w_tr' },
]

type Shaped = Pick<DashboardWidget, 'widget_type' | 'w' | 'h' | 'config'>

function specOf(w: Shaped): { id?: string; metric?: string } {
  const c = w.config as { id?: unknown; data?: { metric?: unknown } } | undefined
  return {
    id: typeof c?.id === 'string' ? c.id : undefined,
    metric: typeof c?.data?.metric === 'string' ? c.data.metric : undefined,
  }
}

export interface LayoutHint {
  template: TemplateKey
  /** Metrics of the template's widgets the copy does not have, in template order. */
  missing: string[]
  /**
   * The template's widgets the copy has (same ids) are in another order or
   * of another size than in the template: the template was rearranged.
   */
  rearranged: boolean
}

/**
 * True when the copy's template widgets (matched by id) are not in the
 * template's order, or not of the template's size.
 */
function isRearranged(layout: readonly Shaped[], tpl: DashboardTemplate): boolean {
  const want = new Map(tpl.widgets.map((w, i) => [specOf(w).id, { i, w: w.w, h: w.h }]))
  let last = -1
  for (const w of layout) {
    const t = want.get(specOf(w).id)
    if (!t) continue
    if (t.i < last || t.w !== w.w || t.h !== w.h) return true
    last = t.i
  }
  return false
}

/** The hint for a personal copy of an offered template that lacks some of its widgets. */
export function layoutHintFor(
  d: Pick<Dashboard, 'layout' | 'kind'> | undefined
): LayoutHint | null {
  if (!d || d.kind === 'organization') return null
  const specs = (d.layout ?? []).map(specOf)
  const have = new Set(specs.map((s) => s.metric).filter(Boolean))
  for (const { key, prefix } of OFFERED) {
    if (specs.filter((s) => s.id?.startsWith(prefix)).length < 3) continue
    const tpl = templateByKey(key)
    const missing = tpl.widgets
      .map((w) => specOf(w).metric)
      .filter((m): m is string => !!m && !have.has(m))
    const rearranged = isRearranged(d.layout ?? [], tpl)
    return missing.length || rearranged
      ? { template: key, missing: [...new Set(missing)], rearranged }
      : null
  }
  return null
}

/** A copy of a template widget with an id not taken in `taken`. */
function copyWidget(w: Shaped, taken: Set<string | undefined>): DashboardWidget {
  const config = structuredClone(w.config) as Record<string, unknown>
  const base = String(config.id)
  let id = base
  for (let n = 2; taken.has(id); n++) id = `${base}_${n}`
  taken.add(id)
  config.id = id
  return { widget_type: w.widget_type, x: 0, y: 0, w: w.w, h: w.h, config }
}

/**
 * The layout with the template's missing widgets added: a single figure
 * right after the nearest template widget before it (keeping the figure row
 * together), a larger widget right before the nearest one after it (beside
 * the same neighbour as in the template), else last. Every widget already there keeps its place, size and
 * settings.
 */
export function withTemplateWidgets(
  layout: DashboardWidget[],
  tpl: DashboardTemplate,
  missing: readonly string[]
): DashboardWidget[] {
  const out = [...layout]
  const taken = new Set(out.map((w) => specOf(w).id))
  const order = tpl.widgets.map((w) => specOf(w).metric)
  const indexOf = (metric: string | undefined) =>
    metric ? out.findIndex((w) => specOf(w).metric === metric) : -1
  tpl.widgets.forEach((tw, i) => {
    const metric = order[i]
    if (!metric || !missing.includes(metric) || indexOf(metric) !== -1) return
    const after = () => {
      for (let j = i - 1; j >= 0; j--) {
        const k = indexOf(order[j])
        if (k !== -1) return k + 1
      }
      return -1
    }
    const before = () => {
      for (let j = i + 1; j < order.length; j++) {
        const k = indexOf(order[j])
        if (k !== -1) return k
      }
      return -1
    }
    // A single figure joins the figure row after its predecessor; a larger
    // widget goes before its successor, beside the same neighbour as in the
    // template.
    let at = (tw.h ?? 1) <= 1 ? after() : before()
    if (at === -1) at = (tw.h ?? 1) <= 1 ? before() : after()
    out.splice(at === -1 ? out.length : at, 0, copyWidget(tw, taken))
  })
  return out.map((w, y) => ({ ...w, y }))
}

export function readLayoutHintDismissed(): boolean {
  try {
    return window.localStorage.getItem(LAYOUT_HINT_DISMISSED_KEY) === LAYOUT_HINT_VERSION
  } catch {
    return false
  }
}

export function writeLayoutHintDismissed() {
  try {
    window.localStorage.setItem(LAYOUT_HINT_DISMISSED_KEY, LAYOUT_HINT_VERSION)
  } catch {
    // A per-viewer convenience only.
  }
}
