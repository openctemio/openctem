'use client'

import { EyeOff } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

/**
 * What the default inventory hides, as one chip in the filter row: names
 * awaiting review and names marked not ours (attribution, RFC-036). "Show"
 * lists every attribution; the chip is not dismissible, because it states
 * what the list leaves out.
 */
export function InventoryHiddenChip({ onShowAll }: { onShowAll: () => void }) {
  const { t } = useTranslation()
  return (
    <span
      data-testid="inventory-hidden-chip"
      className="inline-flex max-w-full items-center gap-1.5 rounded-full border bg-muted/50 py-0.5 ps-2.5 pe-1 text-xs text-muted-foreground"
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex min-w-0 items-center gap-1.5" tabIndex={0}>
            <EyeOff className="size-3.5 shrink-0" aria-hidden />
            <span className="truncate">
              {t('assets.hidden.chip', 'Hiding names awaiting review and not ours')}
            </span>
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          {t(
            'assets.hidden.hint',
            'Discovery adds names passively until a scope entry covers them. Names awaiting review and names marked not yours are left out of this list.'
          )}
        </TooltipContent>
      </Tooltip>
      <button
        type="button"
        onClick={onShowAll}
        className="inline-flex h-5 shrink-0 items-center rounded-full border bg-background px-2 font-medium text-foreground hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {t('assets.hidden.show', 'Show')}
      </button>
    </span>
  )
}
