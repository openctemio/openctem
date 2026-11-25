'use client'

/**
 * One emerging-threat alert: score and why, exploit status, what changed,
 * and the affected assets by tier. Everything the server sends (title,
 * description, product, version, asset names) is rendered as plain text.
 */

import { ArrowLeft } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared/components/error-state'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { PageHeader } from '@/features/shared/components/page-header'
import { FeedDataAsOf } from '@/features/threat-intel/components/feed-freshness-banner'
import { PageStack } from '@/features/shared/components/page-stack'
import { Main, useBreadcrumbTitle } from '@/components/layout'
import { formatEpssScore } from '@/lib/epss'
import { useEmergingThreat } from '../api'
import type { EmergingThreatDetail } from '../types'
import { AffectedAssets } from './affected-assets'
import { AlertActions, OutOfScopeHint, TaskCoverageNote } from './alert-actions'
import {
  EtsBreakdownBars,
  EtsCell,
  LevelBadge,
  StateBadge,
  useEventDetail,
  useEventKindLabel,
} from './bits'
import { formatDate } from '@/lib/app-locale'

export function EmergingThreatDetailView({ id }: { id: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useEmergingThreat(id)
  useBreadcrumbTitle(data?.vuln_id)

  return (
    <Main>
      <PageStack>
        <Button asChild variant="ghost" size="sm" className="-ms-2 self-start">
          <Link href="/emerging-threats">
            <ArrowLeft className="me-1 h-4 w-4 rtl:rotate-180" aria-hidden />
            {t('emergingThreats.back')}
          </Link>
        </Button>
        {error ? (
          <ErrorState
            title={t('emergingThreats.loadOneError')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full rounded-xl" />
        ) : (
          <DetailBody alert={data} />
        )}
      </PageStack>
    </Main>
  )
}

function DetailBody({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  return (
    <>
      {/* The alert's level, state, tier and the recommended action are the
          header's facts, under its title: no rows of their own above the
          cards and the affected assets. */}
      <PageHeader
        title={alert.vuln_id}
        description={
          <span className="flex flex-col gap-2">
            <span className="flex flex-wrap items-center gap-2">
              {alert.title && <span>{alert.title}</span>}
              <FeedDataAsOf className="text-muted-foreground" />
            </span>
            <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <LevelBadge level={alert.level} />
              <StateBadge state={alert.state} />
              <span>{t(`emergingThreats.tier.${alert.tier}`)}</span>
              {alert.state === 'not_affected' && (
                <span>
                  {t(
                    `emergingThreats.notAffected.reasons.${alert.state_reason}`,
                    alert.state_reason
                  )}
                  {alert.suppressed_until && (
                    <>
                      {', '}
                      {t('emergingThreats.suppressedUntil', undefined, {
                        date: formatDate(new Date(alert.suppressed_until)),
                      })}
                    </>
                  )}
                </span>
              )}
            </span>
            {alert.state === 'not_affected' && alert.state_note && (
              <span className="block">{alert.state_note}</span>
            )}
            <span className="block text-foreground">
              {t(`emergingThreats.action.${alert.recommended_action}`)}
            </span>
          </span>
        }
      >
        <AlertActions alert={alert} />
      </PageHeader>
      <OutOfScopeHint alert={alert} />
      <TaskCoverageNote alert={alert} />

      <div className="grid gap-4 lg:grid-cols-2">
        <ScoreCard alert={alert} />
        <ExploitCard alert={alert} />
      </div>

      {alert.description && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('emergingThreats.detail.description')}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap text-sm text-muted-foreground">{alert.description}</p>
          </CardContent>
        </Card>
      )}

      {/* No events: no card that only says so. */}
      {alert.timeline.length > 0 && <Timeline alert={alert} />}
      <AffectedAssets groups={alert.asset_groups ?? []} />
    </>
  )
}

function ScoreCard({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('emergingThreats.detail.score')}</CardTitle>
        <CardDescription>{t('emergingThreats.detail.scoreHint')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <EtsCell ets={alert.ets} />
        <EtsBreakdownBars breakdown={alert.ets_breakdown} />
      </CardContent>
    </Card>
  )
}

function ExploitCard({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const rows: [string, React.ReactNode][] = [
    [
      t('emergingThreats.detail.kev'),
      alert.in_kev
        ? alert.kev_date_added
          ? t('emergingThreats.detail.kevAdded', undefined, { date: alert.kev_date_added })
          : t('emergingThreats.detail.yes')
        : t('emergingThreats.detail.no'),
    ],
    [
      t('emergingThreats.detail.ransomware'),
      alert.kev_ransomware ? t('emergingThreats.detail.yes') : t('emergingThreats.detail.no'),
    ],
    [
      t('emergingThreats.detail.epss'),
      alert.epss != null ? formatEpssScore(alert.epss, 1) : t('emergingThreats.detail.unknown'),
    ],
    [
      t('emergingThreats.detail.severity'),
      alert.severity ? t(`severity.${alert.severity}`, alert.severity) : '—',
    ],
    [
      t('emergingThreats.detail.cvss'),
      alert.cvss_score != null ? String(alert.cvss_score) : t('emergingThreats.detail.unknown'),
    ],
    [
      t('emergingThreats.detail.published'),
      alert.published_at ? formatDate(new Date(alert.published_at)) : '—',
    ],
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('emergingThreats.detail.exploitStatus')}</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid max-w-sm grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-sm">
          {rows.map(([label, value]) => (
            <div key={label} className="contents">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="text-end">{value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}

function Timeline({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const kindLabel = useEventKindLabel()
  const detailOf = useEventDetail()
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('emergingThreats.detail.timeline')}</CardTitle>
      </CardHeader>
      <CardContent>
        {alert.timeline.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('emergingThreats.detail.noEvents')}</p>
        ) : (
          <ol className="space-y-3">
            {alert.timeline.map((ev, i) => {
              const detail = detailOf(ev)
              return (
                <li key={`${ev.kind}-${ev.at}-${i}`} className="flex items-start gap-3 text-sm">
                  <span aria-hidden className="mt-1.5 size-2 shrink-0 rounded-full bg-info" />
                  <div className="min-w-0">
                    <p className="font-medium">{kindLabel(ev.kind)}</p>
                    {detail && <p className="text-muted-foreground">{detail}</p>}
                    <RelativeTime date={ev.at} />
                  </div>
                </li>
              )
            })}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}
