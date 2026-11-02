'use client'

import * as React from 'react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'

/**
 * Text layout primitives (research/244, type scale). Three rules they hold:
 *
 * - One size per line. A metadata line is `text-meta` (12px) throughout; a
 *   label is muted, never smaller than its value.
 * - Words wrap at word boundaries. A flex child that holds text gets
 *   `min-w-0` and a real basis, so it is never squeezed to a few pixels and
 *   broken letter by letter.
 * - Only tokens (hashes, URLs, keys) may break anywhere, and a long token is
 *   truncated in the middle with the full value in a tooltip.
 */

/**
 * A line of metadata: items in one size, separated by space, not by a glyph
 * (research/248). The gap is 12px; an item that is not self-evident carries an
 * icon or a short label (see MetaItem). Between items there is a visually
 * hidden ", " so a screen reader pauses and a copied line reads "a, b, c".
 */
export function MetaLine({
  items,
  className,
  ...props
}: Omit<React.ComponentProps<'p'>, 'children'> & {
  /** Null and false items are skipped. */
  items: React.ReactNode[]
}) {
  const shown = items.filter((i) => i !== null && i !== undefined && i !== false && i !== '')
  if (shown.length === 0) return null
  return (
    <p
      {...props}
      data-slot="meta-line"
      className={cn(
        // Children inherit the size: a nested RelativeTime or badge text cannot
        // come out larger than the line it sits in.
        'flex min-w-0 flex-wrap items-baseline gap-x-3 text-meta text-muted-foreground',
        className
      )}
    >
      {shown.map((item, i) => (
        <React.Fragment key={i}>
          {i > 0 && <span className="sr-only">, </span>}
          {/* An item wraps as a unit when it fits a line, and by words if not. */}
          <span className="min-w-0 [overflow-wrap:anywhere]">{item}</span>
        </React.Fragment>
      ))}
    </p>
  )
}

/**
 * Two or three parts of ONE label, divided by a 1px rule instead of a glyph
 * (a scoped tag "env | production", a chip with a qualifier). The parts are
 * separate spans; a visually hidden separator sits between them so the label
 * reads and copies as "env: production". Wrap it in an element that carries
 * the aria-label when the whole label needs a custom announcement.
 */
export function LabelSegments({
  segments,
  srSeparator = ': ',
  className,
}: {
  /** Null and false segments are skipped. */
  segments: React.ReactNode[]
  /** Visually hidden text between segments: ": " for key and value, ", " for a qualifier. */
  srSeparator?: string
  className?: string
}) {
  const shown = segments.filter((s) => s !== null && s !== undefined && s !== false && s !== '')
  if (shown.length === 0) return null
  return (
    <span
      data-slot="label-segments"
      className={cn(
        'inline-flex min-w-0 items-stretch overflow-hidden rounded-md border text-meta',
        className
      )}
    >
      {shown.map((segment, i) => (
        <React.Fragment key={i}>
          {i > 0 && <span className="sr-only">{srSeparator}</span>}
          <span className={cn('min-w-0 px-1.5 py-0.5', i > 0 && 'border-l')}>{segment}</span>
        </React.Fragment>
      ))}
    </span>
  )
}

/** "Label value" inside a MetaLine: the label muted, the value in the line's size. */
export function MetaItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      {label} <span className="text-foreground">{children}</span>
    </>
  )
}

export interface KeyValueItem {
  key: string
  label: string
  value: React.ReactNode
  /** The value is a token (hash, URL, key): mono, may break anywhere. */
  token?: boolean
}

/**
 * Label and value pairs. Two columns from `sm` (labels sized to the longest,
 * up to 12rem), stacked on a phone. Label and value share one size; the
 * label is muted.
 */
export function KeyValueList({
  items,
  size = 'body',
  className,
  ...props
}: Omit<React.ComponentProps<'dl'>, 'children'> & {
  items: KeyValueItem[]
  /** `body` (14px) in a detail panel, `meta` (12px) in a dense list row. */
  size?: 'body' | 'meta'
}) {
  return (
    <dl
      {...props}
      data-slot="key-value-list"
      className={cn(
        'grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[minmax(6rem,max-content)_minmax(0,1fr)] sm:gap-y-2',
        size === 'meta' ? 'text-meta' : 'text-body',
        className
      )}
    >
      {items.map((item) => (
        <div key={item.key} className="contents">
          <dt className="text-muted-foreground sm:max-w-48">{item.label}</dt>
          <dd
            className={cn(
              'min-w-0',
              item.token ? 'font-mono [overflow-wrap:anywhere]' : 'break-words'
            )}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

/** Cut a long token in the middle: keeps the start and the end readable. */
export function middleTruncate(text: string, max = 32): string {
  if (text.length <= max) return text
  const keep = Math.max(max - 1, 2)
  const head = Math.ceil(keep / 2)
  const tail = Math.floor(keep / 2)
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`
}

/**
 * A hash, URL or key shown in mono, cut in the middle past `max` characters,
 * with the full value in a tooltip (and for screen readers).
 */
export function TokenText({
  value,
  max = 32,
  className,
}: {
  value: string
  max?: number
  className?: string
}) {
  const short = middleTruncate(value, max)
  const text = (
    <span data-slot="token-text" className={cn('font-mono [overflow-wrap:anywhere]', className)}>
      {short}
    </span>
  )
  if (short === value) return text
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          aria-label={value}
          className="rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {text}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm font-mono text-meta [overflow-wrap:anywhere]">
        {value}
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * One row of a list inside a drawer or panel: the name (and an optional
 * trailing badge or action) on the first line, one MetaLine under it. The
 * name owns the full first line, so it never shares width with the meta and
 * is never squeezed.
 */
export function ListItem({
  title,
  trailing,
  meta,
  className,
  as: Tag = 'li',
}: {
  title: React.ReactNode
  trailing?: React.ReactNode
  /** Items of the meta line (source, first seen, last seen...). */
  meta?: React.ReactNode[]
  className?: string
  as?: 'li' | 'div'
}) {
  return (
    <Tag data-slot="list-item" className={cn('min-w-0 px-3 py-2', className)}>
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0 flex-1 basis-40 break-words text-body font-medium">{title}</div>
        {trailing ? <div className="flex shrink-0 items-center gap-1.5">{trailing}</div> : null}
      </div>
      {meta && meta.length > 0 ? <MetaLine items={meta} className="mt-0.5" /> : null}
    </Tag>
  )
}
