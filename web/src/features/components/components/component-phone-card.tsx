'use client'

import { useTranslation } from '@/context/i18n-provider'
import { MetaLine } from '@/features/shared/components/text-layout'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { toDisplayText } from '@/lib/untrusted-text'
import type { ComponentPackage } from '../api/types'
import { componentHref } from '../lib/links'
import { componentVulnWords } from './component-cells'

/**
 * A package on a phone. Fixed slots, plain text, one fact per element:
 *
 *   lodash ............................................. npm
 *   pkg:npm/lodash
 *   1 critical, 2 high, 1 known exploited
 *   2 versions   3 assets   Fix available   Risk 92
 *
 * The ecosystem slot is always there. A tap on the card opens the package
 * page.
 */
export function ComponentPhoneCard({
  item,
  onOpen,
}: {
  item: ComponentPackage
  onOpen: () => void
}) {
  const { t } = useTranslation()
  const vulns = componentVulnWords(item, t)
  return (
    <div
      data-slot="component-card"
      className="flex cursor-pointer items-start gap-3 px-3 py-3 hover:bg-muted/50"
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('button, a[href], [role="checkbox"]')) return
        onOpen()
      }}
    >
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex min-w-0 items-baseline justify-between gap-3">
          <RowNameLink
            href={componentHref(item.id)}
            onOpen={onOpen}
            className="min-w-0 font-medium"
          >
            {toDisplayText(item.name, 160)}
          </RowNameLink>
          <span data-slot="component-card-ecosystem" className="shrink-0 font-mono text-meta">
            {item.ecosystem || <span className="text-muted-foreground">—</span>}
          </span>
        </div>
        <p className="truncate font-mono text-meta text-muted-foreground" title={item.purl}>
          {toDisplayText(item.purl, 200)}
        </p>
        <p className="text-meta">
          {vulns.length > 0 ? (
            vulns.join(', ')
          ) : (
            <span className="text-muted-foreground">
              {t('components.cell.noVulns', 'No open vulnerabilities')}
            </span>
          )}
        </p>
        <MetaLine
          items={[
            <span key="versions" className="tabular-nums">
              {t(
                'components.mobile.versions',
                '{count, plural, one {# version} other {# versions}}',
                { count: item.versions_in_use }
              )}
            </span>,
            <span key="assets" className="tabular-nums">
              {t('components.mobile.assets', '{count, plural, one {# asset} other {# assets}}', {
                count: item.assets,
              })}
            </span>,
            <span key="fix">
              {item.fix_available
                ? t('components.fix.available', 'Fix available')
                : t('components.mobile.noFix', 'No fix yet')}
            </span>,
            <span key="risk" className="tabular-nums">
              {t('components.mobile.risk', 'Risk {score}', {
                score: Math.round(item.risk_score ?? 0),
              })}
            </span>,
          ]}
        />
      </div>
    </div>
  )
}
