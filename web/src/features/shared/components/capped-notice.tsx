'use client'

import { useTranslation } from '@/context/i18n-provider'

/** One line shown when a register hit its row cap: "Showing the first N of M". */
export function CappedNotice({ loaded, total }: { loaded: number; total: number }) {
  const { t } = useTranslation()
  if (total <= loaded) return null
  return (
    <p className="mt-3 text-sm text-muted-foreground" role="status">
      {t('common.showingFirstOf', 'Showing the first {loaded} of {total}', {
        loaded: loaded.toLocaleString(),
        total: total.toLocaleString(),
      })}
    </p>
  )
}
