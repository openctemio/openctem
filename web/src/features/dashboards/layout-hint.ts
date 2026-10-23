/**
 * The offer shown on a person's copy of a template (Overview or CTEM) when
 * the template has gained widgets since the copy was made: add the missing
 * widgets to it, or switch to a fresh copy of the template (the old
 * dashboard is kept). Stored dashboards are never changed on their own; the
 * person chooses. A dismissal is remembered per template version in this
 * browser (a per-viewer convenience).
 */

import type { Dashboard, DashboardWidget } from './api/dashboards.types'
import { templateByKey, type DashboardTemplate, type TemplateKey } from './templates'

/** Bump when a template offered here gains widgets, so the hint shows again. */
export const LAYOUT_HINT_VERSION = '2'
export const LAYOUT_HINT_DISMISSED_KEY = 'openctem:layout-hint-dismissed'

/** Templates whose copies are offered their new widgets, by widget id prefix. */
const OFFERED: ReadonlyArray<{ key: TemplateKey; prefix: string }> = [
  { key: 'overview', prefix: 'w_ov' },
  { key: 'ctem', prefix: 'w_ct' },
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
    const missing = templateByKey(key)
      .widgets.map((w) => specOf(w).metric)
      .filter((m): m is string => !!m && !have.has(m))
    return missing.length ? { template: key, missing: [...new Set(missing)] } : null
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
