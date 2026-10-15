'use client'

/**
 * Scanner or advisory prose, shown as escaped text: `inline code` spans are
 * the only formatting (advisories write identifiers that way), nothing is
 * parsed as HTML or links. Collapsed to a few lines with "Show more".
 */

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/** Splits on back-ticks: odd parts are code. Unbalanced ticks stay text. */
export function inlineCodeParts(text: string): { code: boolean; text: string }[] {
  const parts = text.split('`')
  if (parts.length % 2 === 0) return [{ code: false, text }]
  return parts.map((p, i) => ({ code: i % 2 === 1, text: p })).filter((p) => p.text !== '')
}

export function AdvisoryText({ text, lines = 4 }: { text: string; lines?: number }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const long = text.length > 280 || text.split('\n').length > lines
  return (
    <div>
      <p
        className={cn(
          'text-sm leading-relaxed break-words whitespace-pre-line text-muted-foreground',
          !open && long && 'line-clamp-4'
        )}
      >
        {inlineCodeParts(text).map((p, i) =>
          p.code ? (
            <code
              key={i}
              className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground"
            >
              {p.text}
            </code>
          ) : (
            <span key={i}>{p.text}</span>
          )
        )}
      </p>
      {long && (
        <button
          type="button"
          className="mt-1 rounded-sm text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          {open
            ? t('findings.drawer.showLess', 'Show less')
            : t('findings.drawer.showMore', 'Show more')}
        </button>
      )}
    </div>
  )
}
