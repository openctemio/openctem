'use client'

/**
 * An identifier as a property value: the value itself, never only an action.
 * The first `chars` characters in mono (the whole value in the tooltip and
 * the accessible name), then a small copy button with a "Copy" tooltip that
 * confirms with a toast. `full` shows the whole value, wrapped.
 */

import * as React from 'react'
import { Copy } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'

export interface IdValueProps {
  value: string
  /** How many characters to show; the whole value is in the tooltip. Default 8. */
  chars?: number
  /** Show the whole value (wrapped) instead of its first characters. */
  full?: boolean
  /** The toast after a copy. Default "ID copied". */
  copiedMessage?: string
  className?: string
}

export function IdValue({
  value,
  chars = 8,
  full = false,
  copiedMessage,
  className,
}: IdValueProps) {
  const { t } = useTranslation()
  const cut = !full && value.length > chars
  const shown = cut ? value.slice(0, chars) : value
  const onCopy = React.useCallback(async () => {
    const ok = await copyToClipboard(value)
    if (!ok) toast.error(t('common.copyFailed', 'Could not copy'))
    else toast.success(copiedMessage ?? t('common.idCopied', 'ID copied'))
  }, [value, copiedMessage, t])
  return (
    <span
      data-slot="id-value"
      className={cn('inline-flex max-w-full items-center gap-1', className)}
    >
      <code
        className={cn('font-mono text-xs', full ? 'break-all' : 'whitespace-nowrap')}
        title={cut ? value : undefined}
        aria-label={cut ? value : undefined}
      >
        {shown}
      </code>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            className="shrink-0"
            aria-label={t('common.copyValue', 'Copy {value}', { value })}
            onClick={() => void onCopy()}
          >
            <Copy className="size-3.5 text-muted-foreground" aria-hidden />
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t('common.copy', 'Copy')}</TooltipContent>
      </Tooltip>
    </span>
  )
}
