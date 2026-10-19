'use client'

/**
 * One emerging-threat alert: score and why, exploit status, what changed,
 * and the affected assets by tier. Everything the server sends (title,
 * description, product, version, asset names) is rendered as plain text.
 */

import { ArrowLeft } from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared/components/error-state'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { PageHeader } from '@/features/shared/components/page-header'
import { Main } from '@/components/layout'
import { formatEpssScore } from '@/lib/epss'
import { useEmergingThreat } from '../api'
import type { EmergingThreatAsset, EmergingThreatDetail, EtsBreakdown } from '../types'
import { AlertActions, OutOfScopeHint, TaskCoverageNote } from './alert-actions'
import {
  EtsCell,
  LevelBadge,
  StateBadge,
  useDateLocale,
  useEventDetail,
  useEventKindLabel,
} from './bits'

export function EmergingThreatDetailView({ id }: { id: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useEmergingThreat(id)

  return (
    <Main>
      <Button asChild variant="ghost" size="sm" className="-ms-2 mb-2">
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
    </Main>
  )
}

function DetailBody({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  return (
    <div className="space-y-5">
      <PageHeader
        title={alert.vuln_id}
        description={
          <span className="flex flex-wrap items-center gap-2">
            {alert.title && <span>{alert.title}</span>}
          </span>
        }
      >
        <AlertActions alert={alert} />
      </PageHeader>
      <OutOfScopeHint alert={alert} />
      <TaskCoverageNote alert={alert} />

      <div className="flex flex-wrap items-center gap-3">
        <LevelBadge level={alert.level} />
        <StateBadge state={alert.state} />
        <span className="text-sm text-muted-foreground">
          {t(`emergingThreats.tier.${alert.tier}`)}
        </span>
        {alert.state === 'not_affected' && (
          <span className="text-sm text-muted-foreground">
            {t(`emergingThreats.notAffected.reasons.${alert.state_reason}`, alert.state_reason)}
            {alert.suppressed_until && (
              <>
                {' · '}
                {t('emergingThreats.suppressedUntil', undefined, {
                  date: new Date(alert.suppressed_until).toLocaleDateString(),
                })}
              </>
            )}
          </span>
        )}
      </div>
      {alert.state === 'not_affected' && alert.state_note && (
        <p className="text-sm text-muted-foreground">{alert.state_note}</p>
      )}

      <p className="rounded-lg border bg-muted/40 p-3 text-sm">
        {t(`emergingThreats.action.${alert.recommended_action}`)}
      </p>

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

      <Timeline alert={alert} />
      <AffectedAssets alert={alert} />
    </div>
  )
}

const PARTS: (keyof Omit<EtsBreakdown, 'total' | 'confidence'>)[] = [
  'exploitation',
  'severity',
  'exposure',
  'freshness',
]

function ScoreCard({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const b = alert.ets_breakdown
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('emergingThreats.detail.score')}</CardTitle>
        <CardDescription>{t('emergingThreats.detail.scoreHint')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <EtsCell ets={alert.ets} />
        <dl className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-sm">
          {PARTS.map((k) => (
            <div key={k} className="contents">
              <dt className="text-muted-foreground">{t(`emergingThreats.breakdown.${k}`)}</dt>
              <dd className="text-end tabular-nums">{b[k]}</dd>
            </div>
          ))}
          <dt className="text-muted-foreground">{t('emergingThreats.breakdown.confidence')}</dt>
          <dd className="text-end tabular-nums">
            {t('emergingThreats.breakdown.multiplier', undefined, {
              value: Number(b.confidence.toFixed(2)),
            })}
          </dd>
          <dt className="font-medium">{t('emergingThreats.breakdown.total')}</dt>
          <dd className="text-end font-semibold tabular-nums">{b.total}</dd>
        </dl>
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
      alert.published_at ? new Date(alert.published_at).toLocaleDateString() : '—',
    ],
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t('emergingThreats.detail.exploitStatus')}</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-1 text-sm">
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
  const dateLocale = useDateLocale()
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
                    <RelativeTime date={ev.at} locale={dateLocale} />
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

function AffectedAssets({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const confirmed = alert.assets.filter((a) => a.tier === 'confirmed' || a.tier === 'likely')
  const possible = alert.assets.filter((a) => a.tier === 'possible')
  return (
    <div className="space-y-4">
      <AssetGroup
        title={t('emergingThreats.assets.confirmed')}
        assets={confirmed}
        empty={t('emergingThreats.assets.noneConfirmed')}
      />
      {possible.length > 0 && (
        <AssetGroup title={t('emergingThreats.assets.possible')} assets={possible} />
      )}
    </div>
  )
}

function AssetGroup({
  title,
  assets,
  empty,
}: {
  title: string
  assets: EmergingThreatAsset[]
  empty?: string
}) {
  const { t } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {title} <span className="text-muted-foreground">({assets.length})</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {assets.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('emergingThreats.assets.asset')}</TableHead>
                <TableHead>{t('emergingThreats.assets.exposure')}</TableHead>
                <TableHead>{t('emergingThreats.assets.criticality')}</TableHead>
                <TableHead>{t('emergingThreats.assets.product')}</TableHead>
                <TableHead>{t('emergingThreats.assets.version')}</TableHead>
                <TableHead>{t('emergingThreats.assets.finding')}</TableHead>
                <TableHead>{t('emergingThreats.assets.task')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {assets.map((a) => (
                <TableRow key={`${a.asset_id}-${a.product}-${a.version_seen}`}>
                  <TableCell>
                    <Link href={`/assets/${a.asset_id}`} className="font-medium hover:underline">
                      {a.asset_name}
                    </Link>
                    <p className="text-xs text-muted-foreground">
                      {a.tier === 'likely' ? t('emergingThreats.assets.likely') : a.asset_type}
                    </p>
                  </TableCell>
                  <TableCell>
                    {a.internet_facing ? (
                      <Badge variant="outline">{t('emergingThreats.assets.internetFacing')}</Badge>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {a.criticality ? t(`criticality.${a.criticality}`, a.criticality) : '—'}
                  </TableCell>
                  <TableCell>{a.product || '—'}</TableCell>
                  <TableCell className="font-mono text-xs">{a.version_seen || '—'}</TableCell>
                  <TableCell>
                    {a.finding_id ? (
                      <Link href={`/findings/${a.finding_id}`} className="hover:underline">
                        {t(`findings.status.${a.finding_status}`, a.finding_status)}
                      </Link>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {a.task_id ? (
                      <Link href={`/remediation/tasks/${a.task_id}`} className="hover:underline">
                        {t('emergingThreats.assets.openTask')}
                      </Link>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
