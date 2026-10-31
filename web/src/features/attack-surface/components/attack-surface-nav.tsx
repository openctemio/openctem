'use client'

import { useMemo } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { SectionTabs, SegmentedLens, type SectionTab } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useVisibleSectionTabs } from '@/lib/permissions'
import { ATTACK_SURFACE_VIEWS, viewOfRoute } from '@/config/attack-surface-views'

const SECTION_ROOT = '/attack-surface'

interface ResolvedView {
  id: string
  tab: SectionTab
  routes: { href: string; label: string }[]
}

/**
 * The navigation of Discovery > Attack surface (research/353 D1, D2): one
 * strip with the five views, and, when the open view has more than one route
 * the user can open, a segmented lens that switches between them. One row of
 * tabs per screen; the lens is the shared `SegmentedLens`.
 *
 * `tabs` are the section's route tabs with their labels already translated;
 * this component only groups them, so a route's gate (module, permission)
 * stays the one written on its tab. A view with no route left is hidden.
 * `counts` are keyed by route; a view shows the sum of its routes' counts.
 */
export function AttackSurfaceNav({
  tabs,
  counts,
  label,
}: {
  tabs: readonly SectionTab[]
  counts?: Readonly<Record<string, number | undefined>>
  label: string
}) {
  const { t } = useTranslation()
  const pathname = usePathname() ?? SECTION_ROOT
  const router = useRouter()
  const visible = useVisibleSectionTabs(tabs)

  const views = useMemo<ResolvedView[]>(() => {
    const byHref = new Map(visible.map((tab) => [tab.href, tab]))
    const out: ResolvedView[] = []
    for (const view of ATTACK_SURFACE_VIEWS) {
      const routes = view.routes
        .filter((r) => byHref.has(r.href))
        .map((r) => ({
          href: r.href,
          label: r.labelKey ? t(r.labelKey, r.label) : (byHref.get(r.href)?.label ?? r.href),
        }))
      if (routes.length === 0) continue
      out.push({
        id: view.id,
        routes,
        tab: {
          label: t(view.labelKey, view.label),
          href: routes[0].href,
          // The section root is matched by equality only, or every route of
          // the section would look like part of the Overview.
          matchPrefix: routes.map((r) => r.href).filter((h) => h !== SECTION_ROOT),
        },
      })
    }
    return out
  }, [visible, t])

  const viewCounts = useMemo(() => {
    if (!counts) return undefined
    const out: Record<string, number | undefined> = {}
    for (const v of views) {
      const known = v.routes.map((r) => counts[r.href]).filter((n): n is number => n != null)
      out[v.tab.href] = known.length ? known.reduce((a, b) => a + b, 0) : undefined
    }
    return out
  }, [counts, views])

  const currentId = viewOfRoute(pathname).id
  const current = views.find((v) => v.id === currentId)
  const activeRoute = current?.routes
    .filter((r) => pathname === r.href || pathname.startsWith(`${r.href}/`))
    .sort((a, b) => b.href.length - a.href.length)[0]?.href

  return (
    <>
      {views.length > 1 && (
        <SectionTabs tabs={views.map((v) => v.tab)} label={label} counts={viewCounts} />
      )}
      {current && current.routes.length > 1 && activeRoute && (
        <SegmentedLens // anatomy-ok: switches between the routes of one view (navigation), not a list's state or view mode
          label={t('attackSurface.view.lensLabel', '{view} views', { view: current.tab.label })}
          value={activeRoute}
          options={current.routes.map((r) => ({
            value: r.href,
            label: r.label,
            count: counts?.[r.href],
          }))}
          onChange={(href) => router.push(href)}
          className="max-w-full self-start overflow-x-auto"
        />
      )}
    </>
  )
}
