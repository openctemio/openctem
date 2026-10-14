'use client'

import * as React from 'react'
import { Check, Copy } from 'lucide-react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { FactChip } from './fact-chip'

export interface MoreChipProps {
  /** What the values are ("IP", "technologies"), for the button's accessible name. */
  label: string
  /** The values the row did not show, as display text. */
  values: string[]
  /** Values are identifiers (IPs, hosts, ports): render them in mono. */
  mono?: boolean
}

/**
 * The "+N" of a chip row. It is a button that opens a popover listing every
 * remaining value (click, tap or keyboard), with one button that copies them
 * all: a hover-only tooltip left the values unreachable on touch screens and
 * inside drawers. Values are scanner-supplied text, rendered as text.
 */
export function MoreChip({ label, values, mono = true }: MoreChipProps) {
  const { t } = useTranslation()
  const [copied, setCopied] = React.useState(false)
  if (values.length === 0) return null
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          // The row opens the detail sheet on click; "+N" only opens its list.
          onClick={(e) => e.stopPropagation()}
          aria-label={t('assets.facts.moreAria', '{count} more {label}: {values}', {
            count: values.length,
            label,
            values: values.join(', '),
          })}
          className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [&>[data-slot=fact-chip]]:hover:bg-accent"
        >
          <FactChip tone="muted" className="tabular-nums">
            +{values.length}
          </FactChip>
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-auto max-w-[min(360px,calc(100vw-32px))] p-0"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-3 border-b px-3 py-2">
          <p className="text-xs font-medium text-muted-foreground">
            {t('assets.facts.moreTitle', '{count} more {label}', { count: values.length, label })}
          </p>
          <button
            type="button"
            className="inline-flex items-center gap-1 rounded text-xs text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            onClick={() => {
              copyToClipboard(values.join('\n'))
              setCopied(true)
            }}
          >
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? t('assets.facts.copied', 'Copied') : t('assets.facts.copyAll', 'Copy all')}
          </button>
        </div>
        <ul className="max-h-64 space-y-1 overflow-y-auto px-3 py-2 text-sm">
          {values.map((v, i) => (
            <li
              key={`${v}-${i}`}
              className={cn(mono ? 'font-mono text-xs break-all' : 'break-words')}
            >
              {v}
            </li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  )
}
