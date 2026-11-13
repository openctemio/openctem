'use client'

import * as React from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { TOKEN_CLASSES, tokenize } from '@/lib/code-tokens'
import { hasHiddenCharacters, toDisplayBlock } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/**
 * The one block of attacker-influenced text in the console (scanner plugin
 * output, a script from a benchmark, a banner, an HTTP body), shown as it is
 * safe to read:
 *
 * - React text inside a `<pre>`: never markdown, never HTML, no auto-linking,
 *   so a `<script>` or a markdown link in the output is just characters;
 * - control and bidi characters made visible as `\u{XXXX}` escapes
 *   (`toDisplayBlock`), so an ANSI sequence or a U+202E override cannot hide
 *   or reorder text; line breaks and tabs are kept;
 * - `dir="ltr"` and bidi isolation, so the page direction cannot flip it;
 * - long tokens wrap anywhere, so a reference list never scrolls the page
 *   sideways;
 * - a bounded height that scrolls, or with `collapseLines` the first lines
 *   and "Show more", so a 64 KiB output does not take the page;
 * - optional shell highlighting: the tokens are still React text;
 * - Copy copies the RAW text (what the scanner sent, or `copyText`: the
 *   commands without their prompts), not the escaped view.
 */

export interface UntrustedTextBlockProps {
  text: string
  /** Accessible name of the block and its Copy button ("Scanner output"). */
  label: string
  className?: string
  /** `shell` highlights the text as a shell script; default plain text. */
  language?: 'shell' | 'text'
  /** A visible caption above the block ("Example output", "Script"). */
  caption?: string
  /** What Copy copies, when it differs from `text` (prompts stripped). */
  copyText?: string
  /** Show this many lines and a "Show more" button when the text is longer. */
  collapseLines?: number
}

export function UntrustedTextBlock({
  text,
  label,
  className,
  language = 'text',
  caption,
  copyText,
  collapseLines,
}: UntrustedTextBlockProps) {
  const { t } = useTranslation()
  const [copied, setCopied] = React.useState(false)
  const [expanded, setExpanded] = React.useState(false)
  const timer = React.useRef<number | undefined>(undefined)
  // A pending reset must not fire after the block is gone (it ran in a torn
  // down test window and failed the whole run with an unhandled error).
  React.useEffect(() => () => window.clearTimeout(timer.current), [])
  const shown = React.useMemo(() => toDisplayBlock(text), [text])
  const hidden = React.useMemo(() => hasHiddenCharacters(text.replace(/\r?\n|\t/g, '')), [text])
  const lines = React.useMemo(() => shown.split('\n'), [shown])
  const collapsible = !!collapseLines && lines.length > collapseLines + 2
  const visible = collapsible && !expanded ? lines.slice(0, collapseLines).join('\n') : shown
  const body = React.useMemo(() => {
    if (language !== 'shell') return visible
    return tokenize(visible, 'shell').map((tok, i) => (
      <span key={i} className={TOKEN_CLASSES[tok.type]}>
        {tok.value}
      </span>
    ))
  }, [visible, language])

  const onCopy = async () => {
    if (await copyToClipboard(copyText ?? text)) {
      setCopied(true)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setCopied(false), 1500)
    }
  }

  return (
    <div className={cn('min-w-0', className)} data-slot="untrusted-text">
      {caption && <p className="mb-1 text-xs font-medium text-muted-foreground">{caption}</p>}
      <div className="relative">
        <pre
          aria-label={label}
          data-testid="untrusted-text-block"
          data-language={language}
          dir="ltr"
          tabIndex={0}
          className={cn(
            'overflow-auto rounded-md border bg-muted/40 p-3 pe-12 font-mono text-xs leading-relaxed whitespace-pre-wrap [overflow-wrap:anywhere] [unicode-bidi:isolate] focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
            !collapseLines && 'max-h-96'
          )}
        >
          {body}
        </pre>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          className="absolute end-1.5 top-1.5 h-7 w-7 p-0"
          onClick={onCopy}
          aria-label={
            copied
              ? t('components.untrustedText.copied', '{label} copied', { label })
              : t('components.untrustedText.copy', 'Copy {label}', {
                  label: label.toLowerCase(),
                })
          }
        >
          {copied ? (
            <Check className="h-3.5 w-3.5" aria-hidden />
          ) : (
            <Copy className="h-3.5 w-3.5" aria-hidden />
          )}
        </Button>
      </div>
      {collapsible && (
        <Button
          type="button"
          variant="link"
          size="sm"
          className="mt-1 h-auto p-0 text-xs"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded
            ? t('components.untrustedText.showLess', 'Show less')
            : t('components.untrustedText.showMore', 'Show {count} more lines', {
                count: lines.length - collapseLines!,
              })}
        </Button>
      )}
      {hidden && (
        <p className="mt-1 text-xs text-muted-foreground">
          {t(
            'components.untrustedText.hidden',
            'Contains control or direction characters, shown as escapes.'
          )}
        </p>
      )}
    </div>
  )
}
