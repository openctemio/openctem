'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SeverityBadge } from '@/features/shared'
import { MetaLine } from '@/features/shared/components/text-layout'
import { toDisplayText } from '@/lib/untrusted-text'
import { CveLink } from './cve-link'
import { exploitWord, formatCatalogDate, formatCatalogEpss } from './vulnerability-catalog-table'
import type { Vulnerability } from '../types'

/**
 * A catalog CVE on a phone. Fixed slots, plain text, one fact per element:
 *
 *   CVE-2099-0101 ................................ Critical
 *   Remote code execution in the request parser
 *   Known exploited, Weaponized
 *   CVSS 9.8   EPSS 97.1%   Published 3 Mar 2099
 *
 * The severity slot is always there. A tap on the card opens the detail
 * sheet; the CVE id opens the vulnerability page.
 */
export function CatalogPhoneCard({ item, onOpen }: { item: Vulnerability; onOpen: () => void }) {
  const { t, locale } = useTranslation()
  const title = toDisplayText(item.title, 300)
  const exploit = exploitWord(item, t)
  const signals = [
    ...(item.cisa_kev ? [t('vulnPage.list.chip.kev', 'Known exploited')] : []),
    ...(exploit ? [exploit] : []),
  ]
  return (
    <div
      data-slot="catalog-card"
      className="flex cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50"
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href], [role="checkbox"]')) return
        onOpen()
      }}
    >
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 items-center justify-between gap-3">
          <CveLink id={item.cve_id} stopPropagation className="min-w-0 truncate font-medium" />
          <SeverityBadge severity={item.severity} className="shrink-0" />
        </div>
        <p className="line-clamp-2 text-meta" title={title}>
          {title || <span className="text-muted-foreground">—</span>}
        </p>
        {signals.length > 0 && <p className="text-meta">{signals.join(', ')}</p>}
        <MetaLine
          items={[
            <span key="cvss" className="tabular-nums">
              {t('exposures.vulnCatalog.card.cvss', 'CVSS {score}', {
                score: item.cvss_score?.toFixed(1) ?? '—',
              })}
            </span>,
            <span key="epss" className="tabular-nums">
              {t('exposures.vulnCatalog.card.epss', 'EPSS {score}', {
                score: formatCatalogEpss(item.epss_score),
              })}
            </span>,
            <span key="published">
              {t('exposures.vulnCatalog.card.published', 'Published {date}', {
                date: formatCatalogDate(item.published_at, locale),
              })}
            </span>,
          ]}
        />
      </div>
    </div>
  )
}
