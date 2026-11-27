'use client'

import { usePathname } from 'next/navigation'
import Link from '@/components/link'
import { Home, MoreHorizontal } from 'lucide-react'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Fragment, useEffect, useRef, useState, type RefObject } from 'react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import {
  breadcrumbIsNamed,
  breadcrumbLabel,
  breadcrumbLabelKey,
  CRUMB_PARENTS,
  recordLabel,
  recordLabelKey,
} from './breadcrumb-labels'
import { breadcrumbHasPage, isIdSegment } from './breadcrumb-routes'
import { NavPendingHint } from './sidebar-link'
import { useBreadcrumbTitles } from './breadcrumb-title'
import { fitCrumbs, planCrumbs } from './breadcrumb-fold'

/**
 * A breadcrumb given by its shell instead of built from the URL (the platform
 * console names its pages from its own navigation). The last level is the
 * current page; an empty list shows no trail (the home page).
 */
export interface CrumbTrail {
  /** Accessible name of the home icon link. */
  homeLabel: string
  levels: { path: string; label: string; hasPage: boolean }[]
}

interface BreadcrumbNavProps {
  /** The levels after home, when the shell names them itself (default: from the URL). */
  trail?: CrumbTrail
  /** Override the auto-generated page title */
  pageTitle?: string
  /** Custom className for the breadcrumb container */
  className?: string
  /** Hide the last segment if it's an ID (useful for detail pages with back button) */
  hideIdSegment?: boolean
}

interface CrumbItem {
  path: string
  label: string
  isLast: boolean
  hasPage: boolean
}

/** The tenant app's trail, built from the URL (empty on the home page). */
function crumbsFromUrl(
  pathname: string,
  opts: {
    hideIdSegment: boolean
    pageTitle?: string
    titles: ReadonlyMap<string, string>
    crumb: (path: string, segment: string) => string
    record: (parent: string | undefined) => string
  }
): CrumbItem[] {
  const { hideIdSegment, pageTitle, titles, crumb, record } = opts
  const segments = pathname.split('/').filter(Boolean)
  if (segments.length === 0) return []

  // A page filed under another level: that level's trail, then this page.
  const parent = CRUMB_PARENTS[pathname]
  if (parent) {
    const above = crumbsFromUrl(parent, { ...opts, pageTitle: undefined })
    return [
      ...above.map((item) => ({ ...item, isLast: false })),
      {
        path: pathname,
        label: crumb(pathname, segments[segments.length - 1]),
        isLast: true,
        hasPage: true,
      },
    ]
  }

  // For detail pages (trailing id), keep the parent as a link and add the
  // record's name as the current page.
  const filteredSegments = [...segments]
  let detailPageLabel: string | null = null
  if (hideIdSegment) {
    while (
      filteredSegments.length > 0 &&
      isIdSegment(filteredSegments[filteredSegments.length - 1])
    ) {
      filteredSegments.pop()
    }
    if (filteredSegments.length < segments.length) {
      detailPageLabel =
        pageTitle || titles.get(pathname) || record(filteredSegments[filteredSegments.length - 1])
    }
  }
  // All segments were ids: home only.
  if (filteredSegments.length === 0) return []

  const items: CrumbItem[] = filteredSegments.flatMap((segment, index) => {
    const path = '/' + filteredSegments.slice(0, index + 1).join('/')
    // On a detail page the parent (e.g. "Findings") is a link, not the current page.
    const isLast = index === filteredSegments.length - 1 && detailPageLabel === null
    const hasPage = breadcrumbHasPage(path)
    // A folder with no page and no name of its own is not a level anyone sees.
    if (!isLast && !hasPage && !isIdSegment(segment) && !breadcrumbIsNamed(path, segment)) return []
    const label = isIdSegment(segment)
      ? (titles.get(path) ?? record(filteredSegments[index - 1]))
      : crumb(path, segment)
    return [{ path, label, isLast, hasPage }]
  })
  if (detailPageLabel) {
    items.push({ path: pathname, label: detailPageLabel, isLast: true, hasPage: true })
  }
  return items
}

export function BreadcrumbNav({
  trail,
  pageTitle,
  className,
  hideIdSegment = true,
}: BreadcrumbNavProps) {
  const pathname = usePathname()
  const { t } = useTranslation()
  // Names pages gave the records in the URL; an id with no name yet shows
  // what kind of record it is ("Scan"), never the id.
  const titles = useBreadcrumbTitles()

  const breadcrumbItems = trail
    ? // A shell's own trail takes the names pages gave their records too, so
      // a record level reads as its name ("Acme"), not its kind.
      trail.levels.map((level, i) => ({
        ...level,
        label: titles.get(level.path) ?? level.label,
        isLast: i === trail.levels.length - 1,
      }))
    : crumbsFromUrl(pathname, {
        hideIdSegment,
        pageTitle,
        titles,
        crumb: (path, segment) => {
          const key = breadcrumbLabelKey(path, segment)
          const label = breadcrumbLabel(path, segment)
          return key ? t(key, label) : label
        },
        record: (parent) => t(recordLabelKey(parent), recordLabel(parent)),
      })
  const navRef = useRef<HTMLElement>(null)
  const folded = useMeasuredFold(navRef, breadcrumbItems)
  if (breadcrumbItems.length === 0) return null
  const homeLabel = trail ? trail.homeLabel : t('nav.item.dashboard', 'Dashboard')

  // Fold by measured width (breadcrumb-fold.ts `fitCrumbs`): the middle
  // levels go into the "…" menu first, then the first level, then the
  // parent, only as far as the trail needs to fit its room, so the names
  // that show are whole. Until the trail is measured (the server render, a
  // browser without layout), it folds by the design's breakpoints
  // (`planCrumbs`). The current page stops at 32 characters with its full
  // name as a tooltip.
  const current = breadcrumbItems[breadcrumbItems.length - 1]
  const ancestors = breadcrumbItems.slice(0, -1)
  const view = folded
    ? measuredView(ancestors, current, folded)
    : breakpointView(planCrumbs(ancestors, current))

  const foldMenu = view.menu && (
    <>
      <BreadcrumbSeparator className={view.menu.className} />
      <BreadcrumbItem className={cn('shrink-0', view.menu.className)}>
        <DropdownMenu>
          <DropdownMenuTrigger
            className="hover:text-foreground flex size-control-xs items-center justify-center rounded-sm"
            aria-label={t('nav.breadcrumb.folded', 'Show the hidden levels')}
            data-testid="breadcrumb-fold"
          >
            <MoreHorizontal className="size-4" aria-hidden />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            {view.menu.items.map(({ item, className: itemClass }) => (
              <DropdownMenuItem
                key={item.path}
                asChild={item.hasPage}
                disabled={!item.hasPage}
                className={itemClass}
              >
                {item.hasPage ? <Link href={item.path}>{item.label}</Link> : item.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </BreadcrumbItem>
    </>
  )

  return (
    <Breadcrumb ref={navRef} className={cn('min-w-0 flex-[1_1_auto] overflow-hidden', className)}>
      <BreadcrumbList className="flex-nowrap overflow-hidden">
        <BreadcrumbItem className="shrink-0" data-crumb="home">
          <BreadcrumbLink asChild>
            <Link href="/" className="flex items-center gap-1">
              <Home className="h-4 w-4" />
              <span className="sr-only">{homeLabel}</span>
              <NavPendingHint quiet />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>

        {view.menu?.after === -1 && foldMenu}
        {view.crumbs.map(({ item, index, current: isCurrent, show, sep }) => (
          <Fragment key={item.path}>
            <BreadcrumbSeparator className={sep} />
            <BreadcrumbItem
              className={cn(
                isCurrent
                  ? 'min-w-0 shrink max-w-[32ch]'
                  : // an ancestor shrinks first, but keeps a few letters and its ellipsis
                    'min-w-8 shrink-[100]',
                show
              )}
            >
              {item.isLast ? (
                <BreadcrumbPage className="truncate" aria-current="page" title={item.label}>
                  {item.label}
                </BreadcrumbPage>
              ) : !item.hasPage ? (
                // A section folder with no page: a link would lead to the 404.
                <span className="truncate" title={item.label}>
                  {item.label}
                </span>
              ) : (
                <BreadcrumbLink asChild>
                  <Link href={item.path} className="truncate" title={item.label}>
                    {item.label}
                    <NavPendingHint quiet />
                  </Link>
                </BreadcrumbLink>
              )}
            </BreadcrumbItem>
            {view.menu?.after === index && foldMenu}
          </Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  )
}

/** One crumb as drawn: its classes per width and its place among the ancestors. */
interface CrumbView {
  item: CrumbItem
  /** Its index among the ancestors; the current page has none. */
  index: number
  current: boolean
  /** The crumb's own visibility classes (empty: always shown). */
  show: string
  /** The separator before it. */
  sep: string
}

interface TrailView {
  crumbs: CrumbView[]
  /** The "…" menu: after which ancestor it sits (-1: right after home). */
  menu: { after: number; className: string; items: { item: CrumbItem; className: string }[] } | null
}

/** The fold by the design's breakpoints, before the trail is measured. */
function breakpointView(plan: ReturnType<typeof planCrumbs<CrumbItem>>): TrailView {
  const SHOW_FROM = { always: '', lg: 'hidden lg:inline-flex', xl: 'hidden xl:inline-flex' }
  const SEP_FROM = { always: '', lg: 'hidden lg:flex', xl: 'hidden xl:flex' }
  const FOLDED_BELOW = { lg: 'lg:hidden', xl: 'xl:hidden' }
  return {
    crumbs: plan.crumbs.map(({ item, role, showFrom }, index) => ({
      item,
      index: role === 'current' ? -2 : index,
      current: role === 'current',
      show: SHOW_FROM[showFrom],
      sep: SEP_FROM[showFrom],
    })),
    // The menu sits where the folded levels were: after the first level
    // (which itself folds below 1024px, so there the menu follows home).
    menu: plan.menuBelow
      ? {
          after: 0,
          className: FOLDED_BELOW[plan.menuBelow],
          items: plan.folded.map(({ item, foldedBelow }) => ({
            item,
            className: FOLDED_BELOW[foldedBelow],
          })),
        }
      : null,
  }
}

/** The fold the measured width asks for: the folded ancestors are in the menu only. */
function measuredView(ancestors: CrumbItem[], current: CrumbItem, folded: number[]): TrailView {
  const isFolded = new Set(folded)
  return {
    crumbs: [
      ...ancestors.flatMap((item, index) =>
        isFolded.has(index) ? [] : [{ item, index, current: false, show: '', sep: '' }]
      ),
      { item: current, index: -2, current: true, show: '', sep: '' },
    ],
    // Folded levels are one run (fitCrumbs folds the middle, then the
    // first, then the parent): the menu sits where that run was.
    menu:
      folded.length > 0
        ? {
            after: folded[0] - 1,
            className: '',
            items: folded.map((i) => ({ item: ancestors[i], className: '' })),
          }
        : null,
  }
}

/** The width of a separator icon (size-3.5) and of the "…" button (size-control-xs). */
const SEPARATOR_PX = 14
const MENU_PX = 24

let measureCanvas: HTMLCanvasElement | null = null

/**
 * Which ancestors fold so the trail fits the nav's width, measured with the
 * trail's own font; null until measured (no layout, no canvas). Re-measured
 * when the nav's width or the labels change, and once the web font loads.
 */
function useMeasuredFold(
  navRef: RefObject<HTMLElement | null>,
  items: CrumbItem[]
): number[] | null {
  const [folded, setFolded] = useState<number[] | null>(null)
  const labels = items.map((i) => i.label)
  const key = labels.join('\u0000')
  useEffect(() => {
    const nav = navRef.current
    if (!nav || labels.length === 0) return
    const measure = () => {
      const list = nav.querySelector<HTMLElement>('[data-slot="breadcrumb-list"]')
      const home = nav.querySelector<HTMLElement>('[data-crumb="home"]')
      const available = nav.clientWidth
      // No layout (a test DOM, a hidden header): the breakpoint fold.
      if (!list || !home || !available) {
        setFolded(null)
        return
      }
      measureCanvas ??= document.createElement('canvas')
      let ctx: CanvasRenderingContext2D | null = null
      try {
        ctx = measureCanvas.getContext('2d')
      } catch {
        ctx = null
      }
      if (!ctx) {
        setFolded(null)
        return
      }
      const pen = ctx
      const style = getComputedStyle(list)
      pen.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
      const text = (s: string) => Math.ceil(pen.measureText(s).width)
      const gap = parseFloat(style.columnGap) || 0
      const next = fitCrumbs({
        available,
        home: home.getBoundingClientRect().width,
        step: SEPARATOR_PX + 2 * gap,
        menu: MENU_PX,
        levels: labels.slice(0, -1).map(text),
        current: Math.min(text(labels[labels.length - 1]), text('0') * 32),
      })
      setFolded((prev) =>
        prev && prev.length === next.length && prev.every((v, i) => v === next[i]) ? prev : next
      )
    }
    measure()
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    observer?.observe(nav)
    let live = true
    void document.fonts?.ready.then(() => live && measure())
    return () => {
      live = false
      observer?.disconnect()
    }
    // The labels are compared by their joined key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navRef, key])
  return folded
}
