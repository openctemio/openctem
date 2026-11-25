'use client'

import { cn } from '@/lib/utils'
import { useRef, type ReactNode } from 'react'
import { usePhoneBarTitle } from '@/components/layout/phone-bar-title'

interface PageHeaderProps {
  title: string
  /** String or rich node (e.g. inline stat chips) shown under the title. */
  description?: ReactNode
  children?: ReactNode
  className?: string
  /** Classes for the actions group, e.g. `basis-full sm:basis-auto` for a toolbar that fills a phone row. */
  actionsClassName?: string
  /**
   * A list/grid ViewSwitcher. It owns the far right of the title row at every
   * width and never wraps with the actions: on a phone the actions drop to their
   * own row under the title, so the switcher sits in the same place on every view.
   */
  viewSwitcher?: ReactNode
  /**
   * A control on the title's line, right after the title text and outside
   * the h1 (e.g. a chevron button that switches between dashboards, so the
   * name is the switcher). Same line on a phone; the phone bar still repeats
   * the plain title.
   */
  titleAction?: ReactNode
}

/**
 * The id of the page title. A page has one PageHeader (one h1); a table with
 * no caption of its own takes its name from it (DataTable).
 */
export const PAGE_TITLE_ID = 'page-title'

/**
 * The title block shrinks and wraps (`flex-1 min-w-0`); the actions keep their
 * size and wrap onto their own line when the row runs out. The title block used
 * to be `shrink-0`, so a long description held it at its one-line width and
 * pushed the actions past the edge of the page, where they were clipped.
 */
export function PageHeader({
  title,
  description,
  children,
  className,
  actionsClassName,
  viewSwitcher,
  titleAction,
}: PageHeaderProps) {
  // Below 768 px the phone bar repeats the title once it has scrolled away.
  const titleRef = useRef<HTMLHeadingElement>(null)
  usePhoneBarTitle(titleRef, title)
  return (
    <div
      data-slot="page-header"
      className={cn(
        'flex min-w-0 flex-wrap items-start justify-between gap-x-4 gap-y-3',
        className
      )}
    >
      {/* One header on every page, at every width: the title and the actions
          share one row, and the description is the row under it. Below 640 px
          every action with an icon is a square icon button there (the kit's
          Button, inside `page-header-actions`): its label stays its accessible
          name and returns from sm. So a phone never gets an action row of its
          own between the title and the description, the title keeps the row,
          and a create button is the same square "+" on every page. The title
          keeps a 96 px basis and its longest word; from sm it keeps 240 px.
          With a view switcher the title yields (basis-32) so the switcher
          stays beside it. */}
      <div
        className={cn(
          'flex-1 sm:min-w-0 sm:basis-60',
          viewSwitcher ? 'min-w-0 basis-32' : 'basis-24'
        )}
      >
        {titleAction ? (
          <div data-slot="page-header-title-line" className="flex min-w-0 items-center gap-1">
            <h1
              id={PAGE_TITLE_ID}
              ref={titleRef}
              className="min-w-0 text-page tracking-tight text-balance"
            >
              {title}
            </h1>
            <div data-slot="page-header-title-action" className="flex shrink-0 items-center">
              {titleAction}
            </div>
          </div>
        ) : (
          <h1 id={PAGE_TITLE_ID} ref={titleRef} className="text-page tracking-tight text-balance">
            {title}
          </h1>
        )}
      </div>
      {/* With both a switcher and actions, from sm they travel as one group: when
          the row runs out the group wraps whole and stays at the far right, so the
          switcher is never left alone on a row. On a phone the group dissolves
          (`contents`): the switcher sits beside the title, the actions under it. */}
      <div
        data-slot="page-header-end"
        className={cn(
          viewSwitcher && children
            ? 'max-sm:contents sm:order-3 sm:ml-auto sm:flex sm:shrink-0 sm:items-center sm:gap-2'
            : 'contents'
        )}
      >
        {viewSwitcher && (
          <div data-slot="page-header-view-switcher" className="order-2 shrink-0 sm:order-3">
            {viewSwitcher}
          </div>
        )}
        {children && (
          // Pages often wrap their buttons in their own <div className="flex gap-2">,
          // which does not wrap and pushed the last button off-screen on narrow
          // widths. Direct child groups wrap too, so the actions always fit.
          <div
            data-slot="page-header-actions"
            className={cn(
              'flex max-w-full shrink-0 flex-wrap items-center gap-2 [&>div]:max-w-full [&>div]:flex-wrap',
              // With a switcher: full row under the title on a phone, left of it from sm.
              viewSwitcher && 'order-3 basis-full sm:order-2 sm:basis-auto',
              actionsClassName
            )}
          >
            {children}
          </div>
        )}
      </div>
      {/* The description is shown at every width on every page (a page never
          hides it on a phone: page-header-guard.test.ts), so sibling tabs keep
          one header height. It is a row of its own under the title row at every
          width (order-last, full basis), never a column inside the title
          block: on a phone that column was squeezed into a few words a line
          beside the header's action. The negative margin takes the row gap
          (12px) back to the 4px a description sits under its title; the cap sits
          on an inner box, so the row never joins the title row. */}
      {description && (
        <div data-slot="page-header-description" className="order-last -mt-2 min-w-0 basis-full">
          <div className="max-w-3xl text-sm text-muted-foreground text-pretty">{description}</div>
        </div>
      )}
    </div>
  )
}
