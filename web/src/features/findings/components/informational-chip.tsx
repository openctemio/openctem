'use client'

import { useState } from 'react'
import { EyeOff } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useUpdatePreferences } from '@/features/account/api/use-preferences'
import { useFindingsCount } from '../api/use-findings-count'
import { refreshFindingQuickViews } from '../api/use-quick-views'
import type { FindingApiFilters } from '../api/finding-api.types'

interface InformationalChipProps {
  /** The list's request: the chip counts what it leaves out. */
  filters: FindingApiFilters
  /** The list leaves informational findings out. */
  hidden: boolean
  /** The list shows them only because the person chose Show (the default hides them). */
  shownForView: boolean
  /** How many are left out, when already known (the open quick view says). */
  knownCount?: number
  /** Show or hide them for this view. */
  onChange: (hidden: boolean) => void
}

const chipClass =
  'inline-flex max-w-full items-center gap-1.5 rounded-full border bg-muted/40 ps-2.5 pe-1 py-0.5 text-xs text-muted-foreground'
const actionClass =
  'rounded-full px-2 py-0.5 font-medium text-foreground hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50'

/**
 * Informational findings are never hidden silently: while the list leaves them
 * out, a quiet chip says how many and offers Show (for this view). After Show,
 * it offers Hide again and to keep showing them as the person's own default
 * (api/docs/architecture/findings-work-views.md).
 */
export function InformationalChip({
  filters,
  hidden,
  shownForView,
  knownCount,
  onChange,
}: InformationalChipProps) {
  const { t } = useTranslation()
  const { updatePreferences, isUpdating } = useUpdatePreferences()
  const [saved, setSaved] = useState(false)
  // How many the list leaves out: the open quick view's own count when the
  // list is exactly that view, else the same request, informational only.
  const fetched = useFindingsCount(
    { ...filters, informational: true },
    hidden && knownCount === undefined
  )
  const count = knownCount ?? fetched

  const saveAsDefault = async () => {
    try {
      await updatePreferences({ findings_informational: 'include' })
      setSaved(true)
      await refreshFindingQuickViews()
      toast.success(
        t('findings.informational.saved', 'Informational findings now show in your work views')
      )
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('findings.informational.saveFailed', 'Could not save your preference')
        )
      )
    }
  }

  if (hidden) {
    // Nothing is left out: nothing to say.
    if (count === 0) return null
    return (
      <span data-testid="informational-chip" data-state="hidden" className={chipClass}>
        <EyeOff className="size-3 shrink-0" aria-hidden />
        <span className="min-w-0 truncate">
          {count === undefined
            ? t('findings.informational.hidden', 'Informational hidden')
            : t('findings.informational.hiddenCount', 'Informational hidden ({count})', {
                count,
              })}
        </span>
        <button type="button" className={actionClass} onClick={() => onChange(false)}>
          {t('findings.informational.show', 'Show')}
        </button>
      </span>
    )
  }
  if (!shownForView || saved) return null
  return (
    <span data-testid="informational-chip" data-state="shown" className={chipClass}>
      <span className="min-w-0 truncate">
        {t('findings.informational.shown', 'Informational shown')}
      </span>
      <button type="button" className={actionClass} onClick={() => onChange(true)}>
        {t('findings.informational.hide', 'Hide')}
      </button>
      <button type="button" className={actionClass} onClick={saveAsDefault} disabled={isUpdating}>
        {t('findings.informational.alwaysShow', 'Always show')}
      </button>
    </span>
  )
}
