'use client'

import { useMemo } from 'react'
import { ArrowRight, ShieldAlert } from 'lucide-react'
import Link from '@/components/link'
import { Progress } from '@/components/ui/progress'
import { useTranslation } from '@/context/i18n-provider'
import { useSecurityOverview } from '../api/use-security-overview'
import { normalizeChecks, safeInternalLink } from '../lib/checks'

/**
 * The security overview in brief, at the top of /settings for owners and
 * administrators: the score, the counts and the first things to fix, each
 * linking to its setting. Renders nothing while loading, on an error or for
 * anyone who cannot read the overview (`enabled` false).
 */
export function SecurityScoreCard({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation()
  const { data } = useSecurityOverview(enabled)
  const todo = useMemo(
    () =>
      normalizeChecks(data?.checks ?? [])
        .filter((c) => c.status === 'risk' || c.status === 'warn')
        .sort((a, b) => (a.status === b.status ? 0 : a.status === 'risk' ? -1 : 1))
        .slice(0, 3),
    [data]
  )
  if (!enabled || !data) return null
  const score = data.score ?? 100
  const risks = data.counts?.risk ?? 0
  const warns = data.counts?.warn ?? 0

  return (
    <section
      aria-labelledby="security-score-title"
      className="grid gap-4 rounded-xl border p-4 md:grid-cols-[minmax(0,18rem)_1fr]"
    >
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-muted-foreground" aria-hidden />
          <h2 id="security-score-title" className="text-sm font-semibold">
            {t('settings.item.security-overview', 'Security overview')}
          </h2>
        </div>
        <p className="text-3xl font-semibold tabular-nums">
          {score}
          <span className="text-base font-normal text-muted-foreground">
            {' '}
            {t('securityOverview.score.outOf', '/ 100')}
          </span>
        </p>
        <Progress
          value={score}
          aria-label={t('securityOverview.score.aria', 'Security score: {score} out of 100', {
            score,
          })}
        />
        <p className="text-xs text-muted-foreground">
          {t('settings.securityCard.counts', '{risks} risks · {warns} warnings', {
            risks,
            warns,
          })}
        </p>
      </div>
      <div className="flex min-w-0 flex-col justify-between gap-2">
        {todo.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t('settings.securityCard.allGood', 'Nothing needs attention right now.')}
          </p>
        ) : (
          <ul className="space-y-1.5">
            {todo.map((c) => {
              const href = safeInternalLink(c.link)
              const title = t(`securityOverview.check.${c.id}.title`, c.id)
              return (
                <li key={c.id} className="flex items-start gap-2 text-sm">
                  <span
                    className={
                      c.status === 'risk'
                        ? 'mt-0.5 shrink-0 rounded bg-destructive/10 px-1.5 text-xs font-medium text-destructive'
                        : 'mt-0.5 shrink-0 rounded bg-amber-500/10 px-1.5 text-xs font-medium text-amber-700 dark:text-amber-400'
                    }
                  >
                    {t(`securityOverview.status.${c.status}`, c.status)}
                  </span>
                  {href ? (
                    <Link href={href} className="min-w-0 hover:underline">
                      {title}
                    </Link>
                  ) : (
                    <span className="min-w-0">{title}</span>
                  )}
                </li>
              )
            })}
          </ul>
        )}
        <Link
          href="/settings/security"
          className="inline-flex items-center gap-1 self-start text-sm font-medium hover:underline"
        >
          {t('settings.securityCard.open', 'Open the security overview')}
          <ArrowRight className="size-3.5 rtl:rotate-180" aria-hidden />
        </Link>
      </div>
    </section>
  )
}
