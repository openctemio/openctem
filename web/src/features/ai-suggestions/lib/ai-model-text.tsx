'use client'

import { useMemo, useState } from 'react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayBlock } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/** The most characters of one model text ever rendered, expanded or not. */
export const AI_TEXT_HARD_MAX = 8000
/** Characters shown before "Show more". */
export const AI_TEXT_COLLAPSED = 600

/**
 * Model output (a reason, a step, a summary, an evidence quote) shown as
 * plain text: React text only, never markdown or HTML, never auto-linked, so
 * an `<img onerror>` or a `[link](javascript:...)` is just characters. Line
 * breaks are kept; control and bidi characters become visible escapes
 * (`toDisplayBlock`); `dir="auto"` with bidi isolation keeps a right-to-left
 * run from reordering the text around it. Long text is cut with "Show more",
 * and nothing past `AI_TEXT_HARD_MAX` is ever rendered.
 */
export function AIModelText({
  text,
  collapsed = AI_TEXT_COLLAPSED,
  className,
}: {
  text: string
  collapsed?: number
  className?: string
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const full = useMemo(() => {
    const capped = text.length > AI_TEXT_HARD_MAX ? `${text.slice(0, AI_TEXT_HARD_MAX)}…` : text
    return toDisplayBlock(capped)
  }, [text])
  const long = full.length > collapsed
  const shown = long && !expanded ? `${full.slice(0, collapsed).trimEnd()}…` : full

  return (
    <div className={cn('min-w-0', className)}>
      <p
        dir="auto"
        data-testid="ai-model-text"
        className="whitespace-pre-wrap break-words text-sm leading-relaxed [unicode-bidi:isolate]"
      >
        {shown}
      </p>
      {long && (
        <Button
          type="button"
          variant="link"
          size="sm"
          className="h-auto p-0 text-xs"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded
            ? t('findings.aiSuggestions.showLess', 'Show less')
            : t('findings.aiSuggestions.showMore', 'Show more')}
        </Button>
      )}
    </div>
  )
}
