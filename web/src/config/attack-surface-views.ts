/**
 * The one tab row of Discovery > Attack surface, in order (owner rule
 * 2026-11-24: one tab level per screen, no second row of route tabs under the
 * section tabs). The order keeps the jobs of research/353 D1 side by side:
 *
 *   Overview                               what my external surface is and how healthy it is
 *   Technologies, Certificates, Web surface what I own on the internet, by kind of object
 *   Exposures, Lookalikes                  what is exposed or risky now
 *   Changes, Page changes                  what changed on the surface and on its pages
 *   Discovery, Review                      whether discovery keeps up, and what waits for a decision
 *
 * The routes stay the tabs of `ATTACK_SURFACE_SECTION_TABS` (their gates and
 * labels live there, and the command palette lists every one). A section tab
 * not listed here is a page opened from another page, not a tab: Posture
 * opens from the Overview's posture section ("View posture details") and the
 * command palette, and the Overview tab stays active on it.
 */
export const ATTACK_SURFACE_TAB_ORDER: readonly string[] = [
  '/attack-surface',
  '/attack-surface/technologies',
  '/attack-surface/certificates',
  '/attack-surface/web',
  '/attack-surface/exposures',
  '/attack-surface/lookalikes',
  '/attack-surface/changes',
  '/attack-surface/pages',
  '/attack-surface/discovery',
  '/attack-surface/review',
]

/** Attack surface pages that open from another page; the Overview tab is active on them. */
export const ATTACK_SURFACE_DETAIL_PAGES: readonly string[] = ['/attack-surface/posture']
