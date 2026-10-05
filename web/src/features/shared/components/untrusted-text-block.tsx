'use client'

import * as React from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { copyToClipboard } from '@/lib/clipboard'
import { hasHiddenCharacters, toDisplayBlock } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'

/**
 * A block of attacker-influenced text (scanner plugin output, a banner, an
 * HTTP body) shown as it is safe to read:
 *
 * - React text inside a `<pre>`: never markdown, never HTML, no auto-linking,
 *   so a `<script>` or a markdown link in the output is just characters;
 * - control and bidi characters made visible as `\u{XXXX}` escapes
 *   (`toDisplayBlock`), so an ANSI sequence or a U+202E override cannot hide
 *   or reorder text; line breaks and tabs are kept;
 * - `dir="ltr"` and bidi isolation, so the page direction cannot flip it;
 * - a bounded height that scrolls, so a 64 KiB output does not take the page;
 * - Copy copies the RAW text (what the scanner sent), not the escaped view.
 */

export interface UntrustedTextBlockProps {
  text: string
  /** Accessible name of the block and its Copy button ("Scanner output"). */
  label: string
  className?: string
}

export function UntrustedTextBlock({ text, label, className }: UntrustedTextBlockProps) {
  const [copied, setCopied] = React.useState(false)
  const shown = React.useMemo(() => toDisplayBlock(text), [text])
  const hidden = React.useMemo(() => hasHiddenCharacters(text.replace(/\r?\n|\t/g, '')), [text])

  const onCopy = async () => {
    if (await copyToClipboard(text)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    }
  }

  return (
    <div className={cn('relative', className)}>
      <pre
        aria-label={label}
        data-testid="untrusted-text-block"
        dir="ltr"
        tabIndex={0}
        className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 pe-12 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words [unicode-bidi:isolate] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {shown}
      </pre>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="absolute end-1.5 top-1.5 h-7 w-7 p-0"
        onClick={onCopy}
        aria-label={copied ? `${label} copied` : `Copy ${label.toLowerCase()}`}
      >
        {copied ? (
          <Check className="h-3.5 w-3.5" aria-hidden />
        ) : (
          <Copy className="h-3.5 w-3.5" aria-hidden />
        )}
      </Button>
      {hidden && (
        <p className="mt-1 text-xs text-muted-foreground">
          Contains control or direction characters, shown as escapes.
        </p>
      )}
    </div>
  )
}
