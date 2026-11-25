'use client'

/**
 * The properties of a record: label and value rows, in groups.
 *
 *   <PropertyList label="Properties">
 *     <PropertyGroup>
 *       <PropertyRow label="Status"><StatusSelect … /></PropertyRow>
 *       <PropertyRow label="Severity">…</PropertyRow>
 *     </PropertyGroup>
 *     <PropertyGroup caption="People">…</PropertyGroup>
 *     <PropertyFold label="Asset, dates and more">
 *       <PropertyGroup>…</PropertyGroup>
 *     </PropertyFold>
 *   </PropertyList>
 *
 * No card: groups are separated by a rule. The list follows the width it is
 * given (a container query): one column in a rail, two columns when it sits
 * under the header on a narrower page. A value that does not fit beside its
 * label goes under it, on the row's whole width, instead of being cut. Below 768 px every row is a 44 px
 * line with the value at the end (also with a 36 px control in it), and a
 * `PropertyFold` keeps the long tail one tap away; from 768 px a fold is
 * always open.
 *
 * Each group is a `dl` of `dt` / `dd` pairs. A row whose value is empty
 * renders nothing, so a caller never guards a row twice.
 */

import * as React from 'react'
import { ChevronDown } from 'lucide-react'

import { cn } from '@/lib/utils'

export interface PropertyListProps {
  /** Accessible name of the whole list, e.g. "Properties". */
  label: string
  children: React.ReactNode
  className?: string
}

export function PropertyList({ label, children, className }: PropertyListProps) {
  return (
    <div
      role="group"
      aria-label={label}
      data-slot="property-list"
      className={cn(
        '@container/props flex min-w-0 flex-col',
        // The first group carries no rule; a group inside a fold keeps its own.
        '[&>[data-slot=property-group]:first-child]:border-t-0 [&>[data-slot=property-group]:first-child]:pt-0',
        className
      )}
    >
      {children}
    </div>
  )
}

export interface PropertyGroupProps {
  /** A short caption above the rows ("People"). */
  caption?: string
  children: React.ReactNode
  className?: string
}

export function PropertyGroup({ caption, children, className }: PropertyGroupProps) {
  const captionId = React.useId()
  return (
    <div
      data-slot="property-group"
      // A captioned group is a named group of its own ("People").
      role={caption ? 'group' : undefined}
      aria-labelledby={caption ? captionId : undefined}
      className={cn(
        'min-w-0 border-t border-border-subtle py-3',
        'max-md:border-t-0 max-md:py-0',
        className
      )}
    >
      {caption && (
        <p
          id={captionId}
          data-slot="property-caption"
          className="mb-1 text-cap-m text-muted-foreground max-md:mt-3 max-md:mb-0"
        >
          {caption}
        </p>
      )}
      <dl className="grid min-w-0 gap-x-8 gap-y-1 max-md:gap-y-0 @2xl/props:grid-cols-2">
        {children}
      </dl>
    </div>
  )
}

export interface PropertyRowProps {
  label: string
  /** The value: text, a link, chips or a control. Empty renders no row. */
  children?: React.ReactNode
  /** A value of several lines (a list of owners): the label stays on the first line. */
  top?: boolean
  className?: string
}

export function PropertyRow({ label, children, top, className }: PropertyRowProps) {
  if (children === null || children === undefined || children === false || children === '')
    return null
  return (
    <div
      data-slot="property-row"
      className={cn(
        // From 768 px the label has a 6.75rem column and the value the rest
        // of the line; a value wider than that place (an e-mail beside its
        // avatar, "2 watchers" in Vietnamese, a long name) goes on a line of
        // its own under the label, with the whole width, instead of being
        // cut. A short value stays beside its label.
        'min-h-control min-w-0 gap-x-3 md:flex md:flex-wrap',
        top ? 'md:items-start' : 'md:items-center',
        // Phone: a full-width 44 px line, the value at the end. The padding is
        // small enough that a 36 px control keeps the line at 44 px (2 + 36 +
        // 2 + the 1 px rule, then the minimum); a value of several lines
        // (`top`) keeps more air above and below.
        'max-md:grid max-md:min-h-touch-target max-md:grid-cols-[auto_minmax(0,1fr)] max-md:items-center max-md:border-b max-md:border-border-subtle',
        top ? 'max-md:py-1.5' : 'max-md:py-0.5',
        className
      )}
    >
      <dt
        className={cn(
          'text-dense text-muted-foreground md:w-[6.75rem] md:shrink-0',
          top && 'md:pt-1.5'
        )}
      >
        {label}
      </dt>
      <dd className="min-w-0 text-dense break-words max-md:flex max-md:flex-col max-md:items-end max-md:text-end md:flex-[1_1_auto]">
        {children}
      </dd>
    </div>
  )
}

export interface PropertyFoldProps {
  /** The closed label, e.g. "Asset, dates and more". */
  label: string
  /** The open label, e.g. "Fewer details". */
  openLabel?: string
  children: React.ReactNode
}

/** Phone only: the rows after the first group stay folded until asked for. */
export function PropertyFold({ label, openLabel, children }: PropertyFoldProps) {
  const [open, setOpen] = React.useState(false)
  const id = React.useId()
  return (
    <>
      <button
        type="button"
        data-slot="property-fold"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((v) => !v)}
        className="flex min-h-touch-target w-full items-center justify-between gap-2 rounded-sm text-start text-body font-semibold focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none md:hidden"
      >
        {open && openLabel ? openLabel : label}
        <ChevronDown
          className={cn('size-4 shrink-0 transition-transform', open && 'rotate-180')}
          aria-hidden
        />
      </button>
      <div id={id} data-slot="property-fold-body" className={cn(!open && 'max-md:hidden')}>
        {children}
      </div>
    </>
  )
}
