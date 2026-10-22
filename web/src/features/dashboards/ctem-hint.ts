/**
 * The one-time offer to people whose dashboard is a copy of the Overview
 * template made before it carried the CTEM loop: add the loop to it, or
 * switch to the CTEM template. Nothing changes until they choose; a
 * dismissal is remembered in this browser (a per-viewer convenience).
 */

import type { Dashboard, DashboardWidget } from './api/dashboards.types'
import { CTEM_LOOP_METRIC, templateByKey } from './templates'

export const CTEM_HINT_DISMISSED_KEY = 'openctem:ctem-hint-dismissed'

function specOfWidget(w: DashboardWidget): { id?: string; metric?: string } {
  const c = w.config as { id?: unknown; data?: { metric?: unknown } } | undefined
  return {
    id: typeof c?.id === 'string' ? c.id : undefined,
    metric: typeof c?.data?.metric === 'string' ? c.data.metric : undefined,
  }
}

/** A personal copy of the Overview template (its widget ids) without the CTEM loop. */
export function needsCtemHint(d: Pick<Dashboard, 'layout' | 'kind'> | undefined): boolean {
  if (!d || d.kind === 'organization') return false
  const specs = (d.layout ?? []).map(specOfWidget)
  if (specs.some((s) => s.metric === CTEM_LOOP_METRIC)) return false
  return specs.filter((s) => s.id?.startsWith('w_ov')).length >= 3
}

/** The CTEM loop widget of the Overview template, with an id free in `layout`. */
function loopWidget(layout: DashboardWidget[]): DashboardWidget {
  const tpl = templateByKey('overview').widgets.find(
    (w) => specOfWidget({ ...w, x: 0, y: 0 }).metric === CTEM_LOOP_METRIC
  )!
  const taken = new Set(layout.map((w) => specOfWidget(w).id))
  const config = structuredClone(tpl.config) as Record<string, unknown>
  let id = String(config.id)
  for (let n = 2; taken.has(id); n++) id = `w_ctem${n}`
  config.id = id
  return { widget_type: tpl.widget_type, x: 0, y: 0, w: tpl.w, h: tpl.h, config }
}

/**
 * The layout with the CTEM loop added after the leading row of single
 * figures (where the Overview template has it); the rest keeps its order.
 */
export function withCtemLoop(layout: DashboardWidget[]): DashboardWidget[] {
  const at = layout.findIndex((w) => (w.h ?? 1) > 1)
  const pos = at === -1 ? layout.length : at
  const loop = loopWidget(layout)
  loop.y = layout[pos]?.y ?? layout.length
  return [...layout.slice(0, pos), loop, ...layout.slice(pos)]
}

export function readCtemHintDismissed(): boolean {
  try {
    return window.localStorage.getItem(CTEM_HINT_DISMISSED_KEY) === '1'
  } catch {
    return false
  }
}

export function writeCtemHintDismissed() {
  try {
    window.localStorage.setItem(CTEM_HINT_DISMISSED_KEY, '1')
  } catch {
    // A per-viewer convenience only.
  }
}
