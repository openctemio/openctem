/**
 * The exposure flow panel is offered once to a dashboard that existed before
 * it (api docs/architecture/dashboards.md, "Exposure flow panel"). The server
 * decides and stays idempotent; this is the client's cheap pre-check so a
 * dashboard that cannot take it never sends a request.
 */

import type { Dashboard, DashboardWidget } from '../api/dashboards.types'

export const FLOW_METRIC = 'exposure.flow'

function metricOf(w: DashboardWidget): string | undefined {
  const c = w.config as { data?: { metric?: unknown } } | undefined
  return typeof c?.data?.metric === 'string' ? c.data.metric : undefined
}

/** True when the layout already holds an exposure flow widget. */
export function hasFlowWidget(layout: DashboardWidget[] | undefined): boolean {
  return (layout ?? []).some((w) => w.widget_type === 'metric' && metricOf(w) === FLOW_METRIC)
}

/**
 * Never offered (`flow_panel_at` null or absent from an older server is not
 * eligible: only an explicit null is), a non-empty layout, and no flow yet.
 */
export function flowPanelEligible(d: Pick<Dashboard, 'flow_panel_at' | 'layout'>): boolean {
  return d.flow_panel_at === null && (d.layout ?? []).length > 0 && !hasFlowWidget(d.layout)
}
