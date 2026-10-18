'use client'

/**
 * Settings › Security overview: one score and a short checklist of what to fix
 * first (sign-in, people, credentials, scanning, organization). The API
 * computes statuses; this component renders the wording from the dictionaries
 * by check id, so every language reads the same overview.
 */

import { AlertCircle, AlertTriangle, CheckCircle2, Info, RefreshCw, XCircle } from 'lucide-react'

import Link from '@/components/link'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import { safeInternalHref } from '@/lib/safe-href'

import { useSecurityOverview } from '../api/use-security-overview'
import {
  groupChecks,
  normalizeChecks,
  safeInternalLink,
  type CheckStatus,
  type OverviewCheck,
} from '../lib/checks'

const STATUS_ICON = {
  risk: { Icon: XCircle, className: 'text-destructive' },
  warn: { Icon: AlertTriangle, className: 'text-warning' },
  pass: { Icon: CheckCircle2, className: 'text-success' },
  info: { Icon: Info, className: 'text-muted-foreground' },
} as const

const STATUS_BADGE: Record<CheckStatus, string> = {
  risk: 'border-destructive/40 text-destructive',
  warn: 'border-warning/50 text-warning',
  pass: 'border-success/40 text-success',
  info: 'text-muted-foreground',
}

function CheckRow({ check }: { check: OverviewCheck }) {
  const { t } = useTranslation()
  const { Icon, className } = STATUS_ICON[check.status]
  const link = safeInternalLink(check.link)
  const base = `securityOverview.check.${check.id}`
  const title = t(`${base}.title`, check.id)
  const desc = t(`${base}.desc.${check.status}`, '', { count: check.count ?? 0 })
  const showCount = check.count !== undefined && check.count > 0 && check.status !== 'pass'
  return (
    <li className="flex items-start gap-3 py-3" data-testid={`check-${check.id}`}>
      <Icon className={cn('mt-0.5 size-5 shrink-0', className)} aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium">{title}</span>
          <Badge variant="outline" className={STATUS_BADGE[check.status]}>
            {t(`securityOverview.status.${check.status}`, check.status)}
          </Badge>
          {showCount && (
            <Badge
              variant="secondary"
              aria-label={t('securityOverview.count', 'Count: {count}', {
                count: check.count ?? 0,
              })}
            >
              {check.count}
            </Badge>
          )}
        </div>
        {desc && <p className="mt-0.5 text-sm text-muted-foreground">{desc}</p>}
      </div>
      {link && check.status !== 'pass' && (
        <Button asChild variant="outline" size="sm" className="shrink-0">
          <Link href={safeInternalHref(link) ?? '/settings/security'}>
            {t('securityOverview.review', 'Review')}
          </Link>
        </Button>
      )}
    </li>
  )
}

function OverviewSkeleton() {
  return (
    <div className="space-y-4" data-testid="security-overview-loading" aria-busy="true">
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-48 w-full" />
      <Skeleton className="h-48 w-full" />
    </div>
  )
}

export function SecurityOverview() {
  const { t } = useTranslation()
  const { data, error, isLoading, isValidating, mutate } = useSecurityOverview()

  const recheck = (
    <Button
      variant="outline"
      size="sm"
      onClick={() => void mutate()}
      disabled={isValidating}
      aria-busy={isValidating}
    >
      <RefreshCw className={cn('me-2 size-4', isValidating && 'animate-spin')} aria-hidden="true" />
      {t('securityOverview.recheck', 'Re-check')}
    </Button>
  )

  if (isLoading) return <OverviewSkeleton />

  // An error is not an empty overview: say it failed and offer a retry.
  if (error || !data) {
    return (
      <Alert variant="destructive" role="alert">
        <AlertCircle className="size-4" />
        <AlertTitle>
          {t('securityOverview.error.title', 'Could not load the security overview')}
        </AlertTitle>
        <AlertDescription>
          <p>
            {error
              ? getErrorMessage(error)
              : t('securityOverview.error.empty', 'The server returned no data.')}
          </p>
          <Button variant="outline" size="sm" className="mt-3" onClick={() => void mutate()}>
            <RefreshCw className="me-2 size-4" aria-hidden="true" />
            {t('securityOverview.error.retry', 'Try again')}
          </Button>
        </AlertDescription>
      </Alert>
    )
  }

  const score = Math.max(0, Math.min(100, Math.round(data.score ?? 0)))
  const counts = data.counts ?? {}
  const groups = groupChecks(normalizeChecks(data.checks ?? []))
  const scoreLabel = t('securityOverview.score.aria', 'Security score: {score} out of 100', {
    score,
  })

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="flex flex-col gap-4 pt-6 sm:flex-row sm:items-center">
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-semibold tabular-nums" data-testid="security-score">
                {score}
              </span>
              <span className="text-sm text-muted-foreground">
                {t('securityOverview.score.outOf', '/ 100')}
              </span>
              <span className="ms-2 text-sm font-medium">
                {t('securityOverview.score.title', 'Security score')}
              </span>
            </div>
            <Progress value={score} aria-label={scoreLabel} />
            <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
              <div className="flex items-center gap-1.5">
                <dt className="text-muted-foreground">
                  {t('securityOverview.counts.risk', 'Risks')}
                </dt>
                <dd className="font-medium tabular-nums" data-testid="count-risk">
                  {counts.risk ?? 0}
                </dd>
              </div>
              <div className="flex items-center gap-1.5">
                <dt className="text-muted-foreground">
                  {t('securityOverview.counts.warn', 'Warnings')}
                </dt>
                <dd className="font-medium tabular-nums" data-testid="count-warn">
                  {counts.warn ?? 0}
                </dd>
              </div>
              <div className="flex items-center gap-1.5">
                <dt className="text-muted-foreground">
                  {t('securityOverview.counts.pass', 'Passed')}
                </dt>
                <dd className="font-medium tabular-nums" data-testid="count-pass">
                  {counts.pass ?? 0}
                </dd>
              </div>
            </dl>
          </div>
          <div className="shrink-0">{recheck}</div>
        </CardContent>
      </Card>

      {groups.map(([group, checks]) => (
        <Card key={group}>
          <CardHeader className="pb-0">
            <CardTitle className="text-base">
              {t(`securityOverview.group.${group}`, group)}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {checks.map((c) => (
                <CheckRow key={c.id} check={c} />
              ))}
            </ul>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
