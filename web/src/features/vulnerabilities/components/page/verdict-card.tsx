'use client'

import { safeInternalHref } from '@/lib/safe-href'
import { CircleCheck, CircleDashed, CircleHelp, CircleAlert } from 'lucide-react'
import Link from '@/components/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { CveExposure, ExposureVerdict } from '../../types/exposure'
import { cveFindingsHref } from '../../lib/vuln-page'

const ICON: Record<ExposureVerdict, typeof CircleAlert> = {
  confirmed: CircleAlert,
  possible: CircleHelp,
  not_affected: CircleCheck,
  no_evidence: CircleDashed,
}

const VERDICT_TEXT: Record<ExposureVerdict, string> = {
  confirmed: 'Affected',
  possible: 'Possibly affected',
  not_affected: 'Not affected',
  no_evidence: 'No evidence',
}

const VERDICT_WHY: Record<ExposureVerdict, string> = {
  confirmed: 'Open findings of this vulnerability are on assets in your scope.',
  possible:
    'Software this vulnerability affects runs on assets in your scope, in a version we cannot read. Check the version to confirm.',
  not_affected:
    'The affected software runs only in versions outside the vulnerable ranges, or every finding is closed.',
  no_evidence:
    'No finding and no software this vulnerability affects is known on the assets in your scope. A scan or an inventory that covers them would tell.',
}

/** "Are we affected?": the verdict and its three buckets, each with its count. */
export function VerdictCard({ cve, exposure }: { cve: string; exposure: CveExposure }) {
  const { t } = useTranslation()
  const v = exposure.verdict
  const Icon = ICON[v]
  const buckets: { key: string; label: string; count: number; note?: string; href?: string }[] = [
    {
      key: 'confirmed',
      label: t('vulnPage.verdict.bucket.confirmed', 'Confirmed'),
      count: exposure.assets.impacted,
      href: exposure.assets.impacted > 0 ? cveFindingsHref(cve, { state: 'open' }) : undefined,
    },
    {
      key: 'possible',
      label: t('vulnPage.verdict.bucket.possible', 'Possible'),
      count: exposure.possible.assets,
      note: exposure.possible.products.join(', ') || undefined,
    },
    {
      key: 'not_affected',
      label: t('vulnPage.verdict.bucket.notAffected', 'Not affected'),
      count: exposure.not_affected.assets,
      note: exposure.not_affected.products.join(', ') || undefined,
    },
  ]
  return (
    <Card data-slot="verdict-card" data-verdict={v}>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">
          {t('vulnPage.verdict.title', 'Are we affected?')}
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <div className="flex items-start gap-3">
          <Icon
            className={cn(
              'mt-0.5 h-6 w-6 shrink-0',
              v === 'confirmed' && 'text-destructive',
              v === 'possible' && 'text-warning',
              v !== 'confirmed' && v !== 'possible' && 'text-muted-foreground'
            )}
            aria-hidden
          />
          <div className="min-w-0">
            <p className="text-lg font-semibold" data-slot="verdict">
              {t(`vulnPage.verdict.${v}`, VERDICT_TEXT[v])}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {t(`vulnPage.verdict.why.${v}`, VERDICT_WHY[v])}
            </p>
          </div>
        </div>
        <ul
          className="grid grid-cols-3 gap-2"
          aria-label={t('vulnPage.verdict.buckets', 'Assets by answer')}
        >
          {buckets.map((b) => {
            const body = (
              <>
                <span className="block text-xs text-muted-foreground">{b.label}</span>
                <span
                  className={cn(
                    'block text-xl font-semibold tabular-nums',
                    b.count === 0 && 'text-muted-foreground'
                  )}
                >
                  {b.count.toLocaleString()}
                </span>
                <span className="block text-xs text-muted-foreground">
                  {t('vulnPage.verdict.assets', '{count, plural, one {asset} other {assets}}', {
                    count: b.count,
                  })}
                </span>
                {b.note && (
                  <span
                    className="mt-0.5 block truncate text-xs text-muted-foreground"
                    title={b.note}
                  >
                    {b.note}
                  </span>
                )}
              </>
            )
            return (
              <li key={b.key} className="min-w-0">
                {b.href ? (
                  <Link
                    href={safeInternalHref(b.href) ?? '/findings'}
                    className="block h-full rounded-md border px-3 py-2 transition-colors hover:bg-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    {body}
                  </Link>
                ) : (
                  <div className="h-full rounded-md border px-3 py-2">{body}</div>
                )}
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
