'use client'

import { useTranslation } from '@/context/i18n-provider'
import { formatNumber } from '@/lib/app-locale'
import Link from '@/components/link'

/**
 * One line shown when a register hit its row cap: "Showing the first N of M".
 * `allHref` is a paginated list of the same rows (the asset inventory), so the
 * rows past the cap are one click away instead of out of reach.
 */
export function CappedNotice({
  loaded,
  total,
  allHref,
}: {
  loaded: number
  total: number
  allHref?: string
}) {
  const { t } = useTranslation()
  if (total <= loaded) return null
  return (
    <p className="mt-3 text-sm text-muted-foreground" role="status">
      {t('common.showingFirstOf', 'Showing the first {loaded} of {total}', {
        loaded: formatNumber(loaded),
        total: formatNumber(total),
      })}
      {allHref ? (
        <>
          {' '}
          <Link href={allHref} className="font-medium text-foreground underline underline-offset-4">
            {t('common.openAllInAssetList', 'Open all {total} in the asset list', {
              total: formatNumber(total),
            })}
          </Link>
        </>
      ) : null}
    </p>
  )
}
