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
import { Fragment } from 'react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import {
  breadcrumbLabel,
  breadcrumbLabelKey,
  recordLabel,
  recordLabelKey,
} from './breadcrumb-labels'
import { breadcrumbHasPage, isIdSegment } from './breadcrumb-routes'
import { NavPendingHint } from './sidebar-link'
import { useBreadcrumbTitles } from './breadcrumb-title'
import { planCrumbs } from './breadcrumb-fold'

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

  const items: CrumbItem[] = filteredSegments.map((segment, index) => {
    const path = '/' + filteredSegments.slice(0, index + 1).join('/')
    const label = isIdSegment(segment)
      ? (titles.get(path) ?? record(filteredSegments[index - 1]))
      : crumb(path, segment)
    // On a detail page the parent (e.g. "Findings") is a link, not the current page.
    const isLast = index === filteredSegments.length - 1 && detailPageLabel === null
    return { path, label, isLast, hasPage: breadcrumbHasPage(path) }
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
    ? trail.levels.map((level, i) => ({ ...level, isLast: i === trail.levels.length - 1 }))
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
  if (breadcrumbItems.length === 0) return null
  const homeLabel = trail ? trail.homeLabel : t('nav.item.dashboard', 'Dashboard')

  // Fold by the design's breakpoints (breadcrumb-fold.ts): middle levels
  // into the "…" menu below 1280px, the first level too below 1024px; the
  // parent and the current page always stay. Ancestors truncate before the
  // current page, which stops at 32 characters with its full name as a tooltip.
  const current = breadcrumbItems[breadcrumbItems.length - 1]
  const plan = planCrumbs(breadcrumbItems.slice(0, -1), current)
  const SHOW_FROM = { always: '', lg: 'hidden lg:inline-flex', xl: 'hidden xl:inline-flex' }
  const SEP_FROM = { always: '', lg: 'hidden lg:flex', xl: 'hidden xl:flex' }
  const FOLDED_BELOW = { lg: 'lg:hidden', xl: 'xl:hidden' }
  // The menu sits where the folded levels were: after the first level (which
  // itself folds below 1024px, so there the menu follows home).
  const foldMenu = plan.menuBelow && (
    <>
      <BreadcrumbSeparator className={FOLDED_BELOW[plan.menuBelow]} />
      <BreadcrumbItem className={cn('shrink-0', FOLDED_BELOW[plan.menuBelow])}>
        <DropdownMenu>
          <DropdownMenuTrigger
            className="hover:text-foreground flex size-control-xs items-center justify-center rounded-sm"
            aria-label={t('nav.breadcrumb.folded', 'Show the hidden levels')}
            data-testid="breadcrumb-fold"
          >
            <MoreHorizontal className="size-4" aria-hidden />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            {plan.folded.map(({ item, foldedBelow }) => (
              <DropdownMenuItem
                key={item.path}
                asChild={item.hasPage}
                disabled={!item.hasPage}
                className={FOLDED_BELOW[foldedBelow]}
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
    <Breadcrumb className={cn('min-w-0 flex-[1_1_auto] overflow-hidden', className)}>
      <BreadcrumbList className="flex-nowrap overflow-hidden">
        <BreadcrumbItem className="shrink-0">
          <BreadcrumbLink asChild>
            <Link href="/" className="flex items-center gap-1">
              <Home className="h-4 w-4" />
              <span className="sr-only">{homeLabel}</span>
              <NavPendingHint quiet />
            </Link>
          </BreadcrumbLink>
        </BreadcrumbItem>

        {plan.crumbs.map(({ item, role, showFrom }) => (
          <Fragment key={item.path}>
            <BreadcrumbSeparator className={SEP_FROM[showFrom]} />
            <BreadcrumbItem
              className={cn(
                role === 'current'
                  ? 'min-w-0 shrink max-w-[32ch]'
                  : // an ancestor shrinks first, but keeps a few letters and its ellipsis
                    'min-w-8 shrink-[100]',
                SHOW_FROM[showFrom]
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
            {role === 'first' && foldMenu}
          </Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  )
}
