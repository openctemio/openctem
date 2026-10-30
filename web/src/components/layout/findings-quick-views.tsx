'use client'

import { usePathname } from 'next/navigation'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlParams } from '@/hooks/use-url-param'
import { useFindingQuickViews } from '@/features/findings/api/use-quick-views'
import {
  QUICK_VIEW_LABELS,
  knownQuickViews,
  quickViewHref,
  quickViewIsActive,
  quickViewLabelKey,
  type QuickViewKey,
} from '@/features/findings/lib/quick-views'
import { NavQuickViewList } from './nav-quick-views'

/** Whether `pathname` is a page of the Findings list (not the approvals inbox). */
export function isFindingsListPath(pathname: string): boolean {
  return pathname === '/findings'
}

/**
 * The built-in views under the Findings row, with live counts. They show on the
 * list page only, so the counts are requested (once, 60 s cache) only there;
 * every other page pays nothing. A view is a link to the list with the API's
 * own params, so the count and the list it opens always agree. A zero count
 * shows nothing; SLA breached is in the error colour when above zero.
 */
export function FindingsQuickViews() {
  const pathname = usePathname()
  const onList = isFindingsListPath(pathname)
  const { t } = useTranslation()
  const search = useUrlParams()
  const { data } = useFindingQuickViews(onList)
  if (!onList) return null
  const views = knownQuickViews(data?.views)
  const include = data?.include_informational ?? false
  return (
    <NavQuickViewList
      label={t('findings.quickView.nav', 'Findings views')}
      fallbackHref="/findings"
      views={views.map((v) => ({
        key: v.key,
        label: t(quickViewLabelKey(v.key), QUICK_VIEW_LABELS[v.key as QuickViewKey]),
        href: quickViewHref(v.params, include),
        count: v.count,
        active: quickViewIsActive(search, v, include),
        danger: v.key === 'sla_breached',
        pin: { kind: 'quick_view' as const, ref: v.key },
      }))}
    />
  )
}
