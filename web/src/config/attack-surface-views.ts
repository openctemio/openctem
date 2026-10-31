/**
 * The five views of Discovery > Attack surface (research/353 D1), each a job
 * an operator comes to the page for:
 *
 *   Overview   what my external surface is and how healthy it is
 *   Inventory  what I own on the internet, by kind of object
 *   Exposures  what is exposed or risky now, and what to fix first
 *   Changes    what changed on the surface and on its pages
 *   Discovery  whether discovery is working and complete, and what waits for a decision
 *
 * The routes stay the tabs of `ATTACK_SURFACE_SECTION_TABS` (their gates and
 * labels live there). A view groups routes: the top strip shows the five
 * views, and a view with more than one visible route shows them as a
 * segmented lens under the strip. The strip has no icons (research/244
 * anatomy): at 1440 px the five views fit without a More menu. A route
 * listed here that is not (yet) a section tab is skipped, so a new tab only has to be listed in one group
 * (`route-links: ignore` marks those not built yet: they show once their tab exists).
 */
export interface AttackSurfaceView {
  id: 'overview' | 'inventory' | 'exposures' | 'changes' | 'discovery'
  label: string
  labelKey: string
  /** The routes of the view, in lens order; the first visible one opens the view. */
  routes: readonly AttackSurfaceViewRoute[]
}

export interface AttackSurfaceViewRoute {
  href: string
  /** The lens label, when the tab label would repeat the view's name. */
  label?: string
  labelKey?: string
}

export const ATTACK_SURFACE_VIEWS: readonly AttackSurfaceView[] = [
  {
    id: 'overview',
    label: 'Overview',
    labelKey: 'attackSurface.view.overview',
    routes: [
      { href: '/attack-surface', label: 'Summary', labelKey: 'attackSurface.view.summary' },
      { href: '/attack-surface/posture' /* route-links: ignore */ },
    ],
  },
  {
    id: 'inventory',
    label: 'Inventory',
    labelKey: 'attackSurface.view.inventory',
    routes: [
      { href: '/attack-surface/technologies' },
      { href: '/attack-surface/certificates' },
      { href: '/attack-surface/web' },
    ],
  },
  {
    id: 'exposures',
    label: 'Exposures',
    labelKey: 'attackSurface.view.exposures',
    routes: [
      { href: '/attack-surface/exposures' /* route-links: ignore */ },
      { href: '/attack-surface/lookalikes' },
    ],
  },
  {
    id: 'changes',
    label: 'Changes',
    labelKey: 'attackSurface.view.changes',
    routes: [
      {
        href: '/attack-surface/changes',
        label: 'Surface',
        labelKey: 'attackSurface.view.surfaceChanges',
      },
      { href: '/attack-surface/pages' /* route-links: ignore */ },
    ],
  },
  {
    id: 'discovery',
    label: 'Discovery',
    labelKey: 'attackSurface.view.discovery',
    routes: [
      {
        href: '/attack-surface/discovery' /* route-links: ignore */,
        label: 'Stages',
        labelKey: 'attackSurface.view.stages',
      },
      {
        href: '/attack-surface/review',
        label: 'Decisions',
        labelKey: 'attackSurface.view.decisions',
      },
    ],
  },
]

/** The view a route belongs to; the Overview for an unlisted attack-surface route. */
export function viewOfRoute(pathname: string): AttackSurfaceView {
  let best: { view: AttackSurfaceView; len: number } | undefined
  for (const view of ATTACK_SURFACE_VIEWS) {
    for (const r of view.routes) {
      const hit = pathname === r.href || pathname.startsWith(`${r.href}/`)
      if (hit && (!best || r.href.length > best.len)) best = { view, len: r.href.length }
    }
  }
  return best?.view ?? ATTACK_SURFACE_VIEWS[0]
}
