'use client'

import * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import Link from '@/components/link'
import { usePathname } from 'next/navigation'
import { TAB_CLASS, TAB_STRIP_CLASS, TabsCount, useTabStripScroll } from '@/components/ui/tab-strip'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

export interface SectionTab {
  label: string
  /** i18n key of the label; `label` is the English fallback. */
  labelKey?: string
  href: string
  /**
   * Optional icon before the label (research/244 D3, tab icon rule). A lucide
   * icon only: SectionTabs draws it at 16px with the default stroke, in the
   * tab's own text colour (muted, foreground when active), never coloured.
   * All tabs of one strip have an icon or none does; a strip that mixes them
   * draws no icons. Each icon is distinct within its strip and says what the
   * tab holds (no generic sparkles, wands or robots). The label is always
   * shown: an icon never replaces it.
   */
  icon?: LucideIcon
  /** Optional: also mark active when the pathname starts with this prefix (or any of these). */
  matchPrefix?: string | readonly string[]
  /**
   * Module the tab's route needs. Tabs of one section can belong to different
   * modules (Business context: Crown jewels | Services | Units); render those
   * strips with `GatedSectionTabs`, which hides a tab whose module is off.
   */
  module?: string
  /** Permission the tab's route needs (ANY of them when an array). */
  permission?: string | string[]
  /** Extra command-palette search words (older names of the page). */
  keywords?: readonly string[]
}

interface SectionTabsProps {
  tabs: readonly SectionTab[]
  className?: string
  /** Accessible name for the tab navigation. */
  label?: string
  /**
   * A count shown after a tab's label, keyed by the tab's href (Assets >
   * Suggestions shows the pending suggestions). Zero and absent show nothing.
   */
  counts?: Readonly<Record<string, number | undefined>>
  /**
   * Words after a tab's count for screen readers only, keyed by href
   * ("assets waiting"): the tab is then read "Needs attention 462 assets
   * waiting". The visible label and number stay the start of the name
   * (WCAG 2.5.3 label in name), so this is never an `aria-label`.
   */
  countUnits?: Readonly<Record<string, string | undefined>>
}

/** An icon and its gap to the label (16px + `gap-1.5`), in px. */
const ICON_WIDTH = 22

/**
 * Whether a strip may draw icons: every tab has one, and no two share one.
 * Exported for the governance test over `config/section-tabs.ts`.
 */
export function stripIconsAllowed(tabs: readonly SectionTab[]): boolean {
  if (tabs.length === 0 || !tabs.every((t) => t.icon)) return false
  return new Set(tabs.map((t) => t.icon)).size === tabs.length
}

/**
 * Whether the strip draws its icons: the strip allows them and every tab
 * with its icon fits `available` px. Otherwise the icons go first; tabs that
 * still do not fit scroll sideways (one swipe row with an edge fade), never
 * into a menu. `widths` are the tabs' widths without icons, `gap` the space
 * between two tabs.
 */
export function iconsFit(
  widths: readonly number[],
  available: number,
  gap: number,
  iconsAllowed: boolean
): boolean {
  if (!iconsAllowed || widths.length === 0) return false
  const total =
    widths.reduce((s, w) => s + w + ICON_WIDTH, 0) + Math.max(0, widths.length - 1) * gap
  return total <= available
}

/**
 * Tabs whose items are routes (e.g. Remediation → Tasks | Solution families,
 * Account → Profile | Security | …). One underline strip, the page's only tab
 * row (research/249 R21). The active tab is derived from the pathname; the
 * most specific match wins, so `/account` is not active on `/account/security`.
 *
 * Tabs that do not fit drop their icons first, then the strip becomes one
 * swipe row (the shared `TAB_STRIP_CLASS` + `useTabStripScroll`): an edge
 * with hidden tabs fades, and the current tab is scrolled into view. Tabs are
 * never wrapped, cut or folded into a menu; labels are always whole.
 */
export function SectionTabs({
  tabs,
  className,
  label = 'Sections',
  counts,
  countUnits,
}: SectionTabsProps) {
  const pathname = usePathname()
  const { t } = useTranslation()
  const navRef = React.useRef<HTMLElement>(null)
  const measureRef = React.useRef<HTMLDivElement>(null)
  const iconsAllowed = stripIconsAllowed(tabs)

  if (process.env.NODE_ENV !== 'production' && tabs.some((tab) => tab.icon) && !iconsAllowed) {
    console.warn(`SectionTabs "${label}": every tab needs its own distinct icon, or none has one.`)
  }

  const matches = (tab: SectionTab) =>
    pathname === tab.href ||
    (typeof tab.matchPrefix === 'string'
      ? pathname.startsWith(tab.matchPrefix)
      : (tab.matchPrefix?.some((p) => pathname.startsWith(p)) ?? false)) ||
    pathname.startsWith(`${tab.href}/`)
  const active = tabs.filter(matches).sort((a, b) => b.href.length - a.href.length)[0]?.href

  // Before the first measurement icons are drawn when allowed (server render,
  // no flash on wide screens).
  const [icons, setIcons] = React.useState(iconsAllowed)

  useTabStripScroll(navRef)

  const tabKey = JSON.stringify(tabs.map((tab) => tab.href))
  const countKey = counts ? JSON.stringify(counts) : ''
  React.useLayoutEffect(() => {
    const nav = navRef.current
    const probe = measureRef.current
    if (!nav || !probe) return
    const measure = () => {
      // Not laid out (hidden, or a test DOM): keep the first guess.
      if (nav.clientWidth === 0) return
      const widths = Array.from(probe.querySelectorAll<HTMLElement>('[data-measure=tab]')).map(
        (el) => el.getBoundingClientRect().width
      )
      const gap = parseFloat(getComputedStyle(nav).columnGap) || 0
      setIcons(iconsFit(widths, nav.clientWidth, gap, iconsAllowed))
    }
    measure()
    const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(measure) : undefined
    ro?.observe(nav)
    return () => ro?.disconnect()
    // tabKey/countKey stand for tabs/counts (new arrays on every render).
  }, [tabKey, countKey, iconsAllowed, t])

  const text = (tab: SectionTab) => (tab.labelKey ? t(tab.labelKey, tab.label) : tab.label)
  const count = (tab: SectionTab) => {
    if (!counts?.[tab.href]) return null
    const unit = countUnits?.[tab.href]
    return (
      <>
        <TabsCount value={counts[tab.href]} />
        {unit && <span className="sr-only"> {unit}</span>}
      </>
    )
  }

  return (
    // data-slot: a `PageStack` places the strip (16px under the page header,
    // 20px above the next block); the strip has no margin of its own.
    <nav
      ref={navRef}
      aria-label={label}
      data-slot="page-tabs"
      data-icons={icons ? 'true' : 'false'}
      className={cn(TAB_STRIP_CLASS, 'relative', className)}
    >
      {tabs.map((tab) => {
        const Icon = icons ? tab.icon : undefined
        return (
          <Link
            key={tab.href}
            href={tab.href}
            aria-current={tab.href === active ? 'page' : undefined}
            className={TAB_CLASS}
          >
            {Icon && <Icon aria-hidden data-slot="tab-icon" />}
            {text(tab)}
            {count(tab)}
          </Link>
        )
      })}
      {/* Zero-size copy of every tab (no icons), measured to decide whether
          the icons fit. Hidden from assistive technology and pointer. */}
      <div
        ref={measureRef}
        aria-hidden
        inert
        className="pointer-events-none invisible absolute start-0 top-0 flex h-0 w-0 overflow-hidden whitespace-nowrap"
      >
        {tabs.map((tab) => (
          <span key={tab.href} data-measure="tab" className={TAB_CLASS}>
            {text(tab)}
            {count(tab)}
          </span>
        ))}
      </div>
    </nav>
  )
}
