'use client'

/**
 * The scans list's Query mode: the same shared field and QueryInput as the
 * findings and assets lists, editing the same state as the facet panel and
 * the search. A filter the controls can show is written back as the page's
 * params; one they cannot goes to `fq` and shows as one Advanced chip under
 * the toolbar in Basic mode (see lib/scan-query.ts). The mode is in the URL
 * (`mode=query`), so a link or a reload opens in it.
 */

import { useTranslation } from '@/context/i18n-provider'
import {
  AdvancedChip,
  queryModeIn,
  useListQueryMode,
  withQueryMode,
} from '@/features/query/components/query-mode'
import { applyScanTextFilter, SCAN_FQ_PARAM, scanFilterParams } from '../lib/scan-query'

/** The search field's Query mode on the scans list. */
export function useScanQueryMode(
  search: URLSearchParams,
  onSearchChange: (next: URLSearchParams) => void,
  resultCount?: number | null
) {
  const { t } = useTranslation()
  return useListQueryMode({
    entity: 'scans',
    active: queryModeIn(search),
    onActiveChange: (on) => onSearchChange(withQueryMode(search, on)),
    fq: search.get(SCAN_FQ_PARAM),
    params: scanFilterParams(search),
    onApply: (r, on) => onSearchChange(withQueryMode(applyScanTextFilter(search, r), on)),
    resultCount,
    recentScope: 'scans',
    ariaLabel: t('scans.query.label'),
    testId: 'scans-query-editor',
  })
}

/** The fq filter as one Advanced chip: its text opens Query mode, X removes it. */
export function ScanQueryChip({
  search,
  onOpen,
  onSearchChange,
}: {
  search: URLSearchParams
  onOpen: () => void
  onSearchChange: (next: URLSearchParams) => void
}) {
  const fq = search.get(SCAN_FQ_PARAM)
  if (!fq) return null
  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="scans-query-bar">
      <AdvancedChip
        text={fq}
        onOpen={onOpen}
        onRemove={() => {
          const next = new URLSearchParams(search)
          next.delete(SCAN_FQ_PARAM)
          next.delete('page')
          onSearchChange(next)
        }}
      />
    </div>
  )
}
