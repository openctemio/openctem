/**
 * Dashboard templates as typed widget configs (templates.json). A template is
 * copied into a stored dashboard (personal, or organization for managers);
 * the copy is computed like any dashboard, in the scope of its kind. The API
 * test dashboard_templates_test.go validates every widget of templates.json
 * against the server's spec rules and catalog, so a template can never be
 * refused on save.
 */

import type { DashboardWidget } from './api/dashboards.types'
import raw from './templates.json'

export type TemplateKey = 'overview' | 'executive' | 'program' | 'triage'

export interface DashboardTemplate {
  key: TemplateKey
  columns: number
  widgets: Array<Pick<DashboardWidget, 'widget_type' | 'w' | 'h' | 'config'>>
}

export const DASHBOARD_TEMPLATES = raw as DashboardTemplate[]

/** The template a person without any dashboard starts from. */
export const DEFAULT_TEMPLATE: TemplateKey = 'overview'

export function templateByKey(key: TemplateKey): DashboardTemplate {
  return DASHBOARD_TEMPLATES.find((t) => t.key === key) ?? DASHBOARD_TEMPLATES[0]
}

/** Message keys of a template's name and description. */
export function templateNameKey(key: TemplateKey): string {
  return `dashboards.template.${key}.name`
}
export function templateDescriptionKey(key: TemplateKey): string {
  return `dashboards.template.${key}.description`
}

/** The layout to store for a copy of the template (reading order). */
export function templateLayout(tpl: DashboardTemplate): DashboardWidget[] {
  return tpl.widgets.map((w, i) => ({
    widget_type: w.widget_type,
    x: 0,
    y: i,
    w: w.w,
    h: w.h,
    config: structuredClone(w.config),
  }))
}
