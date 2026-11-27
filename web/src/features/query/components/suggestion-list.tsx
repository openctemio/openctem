'use client'

/**
 * The search box's suggestion list: a listbox the field controls by
 * aria-activedescendant (the caret never leaves the field). A field row
 * reads as the name to type, what the field means and the kind of value it
 * takes; with nothing typed the fields come under their group headings
 * (common, asset, more, identifiers), each heading the label of a group of
 * options.
 */

import { useEffect, type ComponentPropsWithRef } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { QueryEntity } from '../api/query-api'
import { formatCount, type Completion } from '../lib/complete'

// Operator words, by the operator a row ends with.
const OPERATOR_KEYS: Record<string, string> = {
  '=': 'eq',
  '!=': 'ne',
  '>=': 'gte',
  '<=': 'lte',
  '>': 'gt',
  '<': 'lt',
  '~': 'contains',
}

interface Run {
  group?: string
  items: { option: Completion; index: number }[]
}

/** Consecutive options under one heading (no heading: one run). */
function runsOf(options: Completion[]): Run[] {
  const runs: Run[] = []
  options.forEach((option, index) => {
    const last = runs[runs.length - 1]
    if (last && last.group === option.group) last.items.push({ option, index })
    else runs.push({ group: option.group, items: [{ option, index }] })
  })
  return runs
}

/**
 * The popover it sits in (`PopoverContent asChild`) hands it its class, style,
 * ref and data attributes: they land on the listbox element (`rest`).
 */
export function SuggestionList({
  id,
  entity,
  options,
  active,
  onPick,
  ...rest
}: {
  id: string
  entity: QueryEntity
  options: Completion[]
  active: number
  onPick: (o: Completion) => void
} & Omit<ComponentPropsWithRef<'div'>, 'id' | 'role'>) {
  const { t, locale } = useTranslation()

  // The active row stays in view as the arrows move through a long list.
  useEffect(() => {
    document.getElementById(`${id}-${active}`)?.scrollIntoView?.({ block: 'nearest' })
  }, [id, active])

  const detail = (o: Completion): { text: string; tag?: string } => {
    if (o.count !== undefined) return { text: '', tag: formatCount(o.count, locale) }
    if (o.kind === 'field' && o.field) {
      return {
        text: t(`queryFields.${entity}.${o.field.path}`, t('queryInput.kind.field')),
        tag: t(`queryInput.type.${o.field.type}`, ''),
      }
    }
    if (o.kind === 'operator') {
      const op = OPERATOR_KEYS[o.label.replace(/^[\w.]+/, '')]
      return { text: op ? t(`queryInput.op.${op}`) : t('queryInput.kind.operator') }
    }
    return { text: '', tag: t(`queryInput.kind.${o.kind}`) }
  }

  const row = ({ option: o, index: i }: Run['items'][number]) => {
    const d = detail(o)
    // A field or operator name is never cut; a long value or recent query is.
    const named = o.kind === 'field' || o.kind === 'operator'
    return (
      <li
        key={`${o.kind}-${o.label}`}
        id={`${id}-${i}`}
        role="option"
        aria-selected={i === active}
        className={cn(
          'flex min-h-8 cursor-pointer items-center gap-3 rounded px-2 py-1 text-xs md:min-h-6',
          i === active && 'bg-accent text-accent-foreground'
        )}
        onMouseDown={(e) => {
          e.preventDefault()
          onPick(o)
        }}
      >
        <span className={cn('font-mono', named ? 'shrink-0' : 'min-w-0 flex-1 truncate')}>
          {o.label}
        </span>
        {d.text && (
          <span
            className={cn(
              'min-w-0 flex-1 truncate',
              i === active ? 'text-accent-foreground/80' : 'text-muted-foreground'
            )}
          >
            {d.text}
          </span>
        )}
        {!d.text && named && <span className="flex-1" aria-hidden />}
        {d.tag && (
          // A field's value kind gives way to its meaning on a phone.
          <span
            className={cn(
              'text-muted-foreground text-cap shrink-0',
              o.kind === 'field' && 'hidden md:inline'
            )}
          >
            {d.tag}
          </span>
        )}
      </li>
    )
  }

  return (
    <div {...rest} id={id} role="listbox" aria-label={t('queryInput.suggestions')}>
      {runsOf(options).map((run, r) => {
        if (!run.group) {
          return (
            <ul key={`run-${r}`} role="presentation">
              {run.items.map(row)}
            </ul>
          )
        }
        const headingId = `${id}-group-${r}`
        return (
          <ul key={`run-${r}`} role="group" aria-labelledby={headingId}>
            <li
              role="presentation"
              id={headingId}
              className={cn(
                'text-muted-foreground text-cap-m px-2 pb-1',
                r === 0 ? 'pt-1' : 'pt-2'
              )}
            >
              {t(`queryInput.group.${run.group}`, run.group)}
            </li>
            {run.items.map(row)}
          </ul>
        )
      })}
    </div>
  )
}
