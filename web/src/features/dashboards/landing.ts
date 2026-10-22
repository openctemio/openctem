/**
 * Which dashboard `/` opens (api docs/architecture/dashboards.md, "Ownership"):
 * the one the viewer last chose while it still exists, else their own
 * default, else the organization default (for organization viewers), else
 * the first organization dashboard, else their first own dashboard.
 */

import type { Dashboard, DashboardKind } from './api/dashboards.types'

export interface DashboardRef {
  kind: DashboardKind
  id: string
}

/** localStorage key of the viewer's last choice (a per-viewer convenience). */
export const DASHBOARD_CHOICE_KEY = 'openctem:dashboard-choice'

export function refKey(ref: DashboardRef): string {
  return `${ref.kind}:${ref.id}`
}

export function parseRef(raw: string | null | undefined): DashboardRef | null {
  if (!raw) return null
  const i = raw.indexOf(':')
  if (i < 0) return null
  const kind = raw.slice(0, i)
  const id = raw.slice(i + 1)
  if ((kind !== 'personal' && kind !== 'organization') || !id) return null
  return { kind, id }
}

export function pickLanding(
  personal: readonly Dashboard[],
  organization: readonly Dashboard[],
  saved: DashboardRef | null
): DashboardRef | null {
  const has = (ref: DashboardRef) =>
    (ref.kind === 'personal' ? personal : organization).some((d) => d.id === ref.id)
  if (saved && has(saved)) return saved
  const mine = personal.find((d) => d.is_default)
  if (mine) return { kind: 'personal', id: mine.id }
  const orgDefault = organization.find((d) => d.is_org_default) ?? organization[0]
  if (orgDefault) return { kind: 'organization', id: orgDefault.id }
  if (personal[0]) return { kind: 'personal', id: personal[0].id }
  return null
}
