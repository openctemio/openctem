'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'

import { EDGE_FIXES, EDGE_FIX_HREFS, type EdgeGapKind } from '../lib/edge-gap'

/**
 * How to fix a host an edge protection stopped, or that kept rate limiting
 * the scan: a compact row of links to where each fix is applied. The one
 * place this is written; the run page and the asset coverage section both
 * render it.
 */
export function EdgeGapFixes({ kind }: { kind: EdgeGapKind }) {
  const { t } = useTranslation()
  return (
    <p
      className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 text-xs"
      data-testid="edge-gap-fixes"
    >
      <span className="font-medium text-foreground">{t('scans.edgeGap.howToFix')}</span>
      {EDGE_FIXES[kind].map((fix) => (
        <Link
          key={fix}
          href={EDGE_FIX_HREFS[fix]}
          className="text-primary underline-offset-4 hover:underline"
        >
          {t(`scans.edgeGap.fix.${fix}`)}
        </Link>
      ))}
    </p>
  )
}
