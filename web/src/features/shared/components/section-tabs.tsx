'use client'

import * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { ChevronDown } from 'lucide-react'
import Link from '@/components/link'
import { usePathname } from 'next/navigation'
import { TAB_CLASS, TabsCount } from '@/components/ui/tabs'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
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
}

/** Space between two tabs (`gap-6`), in px. */
const TAB_GAP = 24
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

export interface TabFit {
  /** Draw the icons (they fit, and the strip allows them). */
  icons: boolean
  /** Indexes of the tabs shown in the strip, in order. */
  visible: number[]
  /** Indexes of the tabs listed under More. */
  overflow: number[]
}

/**
 * Which tabs fit in `available` px (research/244 mobile decision M1, the
 * priority-plus pattern): every tab with its icon if they all fit; else every
 * tab without icons; else as many as fit beside a More button, the rest in
 * its menu. The current tab is always one of the shown tabs (it takes the
 * last shown slot when it would fall into the menu), so a page never hides
 * where you are. `widths` are the tabs' widths without icons.
 */
export function fitTabs(
  widths: readonly number[],
  available: number,
  moreWidth: number,
  activeIndex: number,
  iconsAllowed: boolean
): TabFit {
  const all = widths.map((_, i) => i)
  const total = (ws: readonly number[]) =>
    ws.reduce((s, w) => s + w, 0) + Math.max(0, ws.length - 1) * TAB_GAP
  if (iconsAllowed && total(widths.map((w) => w + ICON_WIDTH)) <= available) {
    return { icons: true, visible: all, overflow: [] }
  }
  if (total(widths) <= available) return { icons: false, visible: all, overflow: [] }
  // Fill from the start, leaving room for More.
  const room = available - moreWidth - TAB_GAP
  let used = 0
  let count = 0
  for (const w of widths) {
    const next = used + (count > 0 ? TAB_GAP : 0) + w
    if (next > room) break
    used = next
    count++
  }
  let visible = all.slice(0, Math.max(count, 1))
  if (activeIndex >= visible.length) {
    // Swap the current tab into the strip; drop shown tabs from the end until
    // it fits (always keep at least the current tab).
    visible = [...visible, activeIndex]
    while (visible.length > 1 && total(visible.map((i) => widths[i])) > room) {
      visible.splice(visible.length - 2, 1)
    }
  }
  const shown = new Set(visible)
  return { icons: false, visible, overflow: all.filter((i) => !shown.has(i)) }
}

/**
 * Tabs whose items are routes (e.g. Remediation → Tasks | Solution families,
 * Account → Profile | Security | …). One underline strip, the page's only tab
 * row (research/249 R21). The active tab is derived from the pathname; the
 * most specific match wins, so `/account` is not active on `/account/security`.
 *
 * Tabs that do not fit never scroll or get cut ("Approv…"): the strip first
 * drops its icons, then moves the last tabs into a More menu, keeping the
 * current tab in view. Labels are always whole.
 */
export function SectionTabs({ tabs, className, label = 'Sections', counts }: SectionTabsProps) {
  const pathname = usePathname()
  const { t } = useTranslation()
  const navRef = React.useRef<HTMLElement>(null)
  const measureRef = React.useRef<HTMLDivElement>(null)
  const iconsAllowed = stripIconsAllowed(tabs)

  if (process.env.NODE_ENV !== 'production' && tabs.some((tab) => tab.icon) && !iconsAllowed) {
    console.warn(
      `SectionTabs "${label}": every tab needs its own distinct icon, or none has one; drawing no icons (research/244 D3).`
    )
  }

  const matches = (tab: SectionTab) =>
    pathname === tab.href ||
    (typeof tab.matchPrefix === 'string'
      ? pathname.startsWith(tab.matchPrefix)
      : (tab.matchPrefix?.some((p) => pathname.startsWith(p)) ?? false)) ||
    pathname.startsWith(`${tab.href}/`)
  const active = tabs.filter(matches).sort((a, b) => b.href.length - a.href.length)[0]?.href
  const activeIndex = tabs.findIndex((tab) => tab.href === active)

  // Before the first measurement every tab is drawn (server render, no flash
  // of a More menu on wide screens); the strip clips rather than scrolls.
  const [fit, setFit] = React.useState<TabFit>(() => ({
    icons: iconsAllowed,
    visible: tabs.map((_, i) => i),
    overflow: [],
  }))

  const tabKey = JSON.stringify(tabs.map((tab) => tab.href))
  const countKey = counts ? JSON.stringify(counts) : ''
  React.useLayoutEffect(() => {
    const nav = navRef.current
    const probe = measureRef.current
    if (!nav || !probe) return
    const measure = () => {
      // Not laid out (hidden, or a test DOM): keep every tab.
      if (nav.clientWidth === 0) return
      const items = Array.from(probe.querySelectorAll<HTMLElement>('[data-measure=tab]'))
      const more = probe.querySelector<HTMLElement>('[data-measure=more]')
      const widths = items.map((el) => el.getBoundingClientRect().width)
      const next = fitTabs(
        widths,
        nav.clientWidth,
        more?.getBoundingClientRect().width ?? 72,
        activeIndex,
        iconsAllowed
      )
      setFit((prev) =>
        prev.icons === next.icons &&
        prev.visible.join() === next.visible.join() &&
        prev.overflow.join() === next.overflow.join()
          ? prev
          : next
      )
    }
    measure()
    const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(measure) : undefined
    ro?.observe(nav)
    return () => ro?.disconnect()
    // tabKey/countKey stand for tabs/counts (new arrays on every render).
  }, [tabKey, countKey, activeIndex, iconsAllowed, t])

  const text = (tab: SectionTab) => (tab.labelKey ? t(tab.labelKey, tab.label) : tab.label)
  const count = (tab: SectionTab) =>
    counts?.[tab.href] ? <TabsCount value={counts[tab.href]} /> : null
  const moreLabel = t('common.tabs.more', 'More')
  const overflowActive = fit.overflow.some((i) => i === activeIndex)

  return (
    // data-slot: a `PageStack` places the strip (16px under the page header,
    // 20px above the next block) and drops the legacy mb-5.
    <nav
      ref={navRef}
      aria-label={label}
      data-slot="page-tabs"
      data-icons={fit.icons ? 'true' : 'false'}
      className={cn(
        'relative flex h-10 w-full max-w-full items-stretch justify-start gap-6 overflow-hidden border-b text-muted-foreground',
        'mb-5',
        className
      )}
    >
      {fit.visible.map((i) => {
        const tab = tabs[i]
        const Icon = fit.icons ? tab.icon : undefined
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
      {fit.overflow.length > 0 && (
        <DropdownMenu>
          <DropdownMenuTrigger
            className={cn(TAB_CLASS, 'cursor-pointer')}
            aria-current={overflowActive ? 'page' : undefined}
            data-slot="tabs-more"
          >
            {moreLabel}
            <ChevronDown aria-hidden />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-44">
            {fit.overflow.map((i) => {
              const tab = tabs[i]
              return (
                <DropdownMenuItem key={tab.href} asChild>
                  <Link
                    href={tab.href}
                    aria-current={tab.href === active ? 'page' : undefined}
                    className="flex items-center justify-between gap-3"
                  >
                    <span>{text(tab)}</span>
                    {count(tab)}
                  </Link>
                </DropdownMenuItem>
              )
            })}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {/* Off-screen copy of every tab (no icons) and of More, measured to
          decide what fits. Hidden from assistive technology and pointer. */}
      <div
        ref={measureRef}
        aria-hidden
        inert
        className="pointer-events-none invisible absolute start-0 top-0 flex h-0 gap-6 overflow-hidden whitespace-nowrap"
      >
        {tabs.map((tab) => (
          <span key={tab.href} data-measure="tab" className={TAB_CLASS}>
            {text(tab)}
            {count(tab)}
          </span>
        ))}
        <span data-measure="more" className={TAB_CLASS}>
          {moreLabel}
          <ChevronDown aria-hidden />
        </span>
      </div>
    </nav>
  )
}
