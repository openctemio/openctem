'use client'

import { useState } from 'react'
import { EyeOff } from 'lucide-react'
import { toast } from 'sonner'
import { LockedChip, LockedChipAction } from '@/features/shared/components/filter-chips-row'
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
  /**
   * How many are left out when the open quick view already says; null while
   * that is not known yet (no request until it is), undefined to count with
   * one request (a list that is not exactly a quick view).
   */
  knownCount?: number | null
  /** Show or hide them for this view. */
  onChange: (hidden: boolean) => void
}

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
  const count = knownCount === null ? undefined : (knownCount ?? fetched)

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
    // Nothing is left out: nothing to say. And nothing until the count is
    // known: a chip drawn first and withdrawn when the count turns out to be
    // zero (the usual case) pushed the list up by a chip row on a phone, where
    // it wraps the row's other controls onto a second line.
    if (count === undefined || count === 0) return null
    return (
      <LockedChip
        data-testid="informational-chip"
        data-state="hidden"
        icon={EyeOff}
        actionLabel={t('findings.informational.show', 'Show')}
        onAction={() => onChange(false)}
      >
        {t('findings.informational.hiddenCount', 'Informational hidden ({count})', { count })}
      </LockedChip>
    )
  }
  if (!shownForView || saved) return null
  return (
    <LockedChip
      data-testid="informational-chip"
      data-state="shown"
      icon={null}
      actions={
        <>
          <LockedChipAction onClick={() => onChange(true)}>
            {t('findings.informational.hide', 'Hide')}
          </LockedChipAction>
          <LockedChipAction onClick={saveAsDefault} disabled={isUpdating}>
            {t('findings.informational.alwaysShow', 'Always show')}
          </LockedChipAction>
        </>
      }
    >
      {t('findings.informational.shown', 'Informational shown')}
    </LockedChip>
  )
}
