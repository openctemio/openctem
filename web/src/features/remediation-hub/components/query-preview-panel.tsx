'use client'

/**
 * What a task from a query would hold, as the server computed it in the
 * caller's own access: how many findings match, by severity, the top assets
 * and owners, a sample, the earliest SLA deadline and a suggested owner.
 * Finding titles and asset names are scanner and user text: rendered as
 * plain text only.
 */

import { useTranslation } from '@/context/i18n-provider'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared/types'
import type { QueryBreakdown, QueryStats, QueryTaskPreview } from '../api/use-task-query'

interface OwnerNames {
  user: (id?: string) => string | undefined
  group: (id?: string) => string | undefined
}

function formatDate(iso?: string): string | null {
  if (!iso) return null
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString()
}

function Breakdown({
  title,
  rows,
  label,
}: {
  title: string
  rows: QueryBreakdown[]
  label: (r: QueryBreakdown) => string
}) {
  if (rows.length === 0) return null
  const max = Math.max(...rows.map((r) => r.count))
  return (
    <section className="space-y-1.5">
      <h4 className="text-muted-foreground text-xs font-medium uppercase">{title}</h4>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.key} className="flex items-center gap-2 text-xs">
            <span className="w-32 shrink-0 truncate" title={label(r)}>
              {label(r)}
            </span>
            <span className="bg-muted h-1.5 flex-1 rounded" aria-hidden>
              <span
                className="bg-primary block h-1.5 rounded"
                style={{ width: `${(r.count / max) * 100}%` }}
              />
            </span>
            <span className="w-10 shrink-0 text-right tabular-nums">{r.count}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

export function QueryPreviewPanel({
  preview,
  ownerName,
}: {
  preview: QueryTaskPreview
  ownerName: OwnerNames
}) {
  const { t } = useTranslation()
  const stats: QueryStats | undefined = preview.stats
  const ownerLabel = (r: QueryBreakdown) =>
    ownerName.user(r.user_id) ??
    ownerName.group(r.group_id) ??
    (r.name || t('remediationQuery.preview.unknownOwner'))
  const suggested = preview.suggested_assignee
  const suggestedName = suggested
    ? (ownerName.user(suggested.user_id) ?? ownerName.group(suggested.group_id) ?? null)
    : null
  const earliest = formatDate(stats?.earliest_deadline)

  return (
    <section
      aria-label={t('remediationQuery.preview.label')}
      aria-live="polite"
      className="space-y-4 rounded-md border p-4"
      data-testid="query-preview"
    >
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1">
        <p className="text-2xl font-semibold tabular-nums">
          {t(
            `remediationQuery.preview.matches.${preview.total === 1 ? 'one' : 'other'}`,
            undefined,
            {
              count: preview.total,
            }
          )}
        </p>
        {!preview.too_many && preview.conflicts.length > 0 && (
          <p className="text-muted-foreground text-sm">
            {t('remediationQuery.preview.claimable', undefined, {
              count: preview.claimable,
              held: preview.conflicts.length,
            })}
          </p>
        )}
      </div>
      <p className="text-muted-foreground text-xs">
        {preview.scope_kind === 'data_scope'
          ? t('remediationQuery.preview.scopeMine')
          : t('remediationQuery.preview.scopeOrg')}{' '}
        {t('remediationQuery.preview.excluded')}
      </p>

      {preview.too_many ? (
        <p role="alert" className="text-destructive text-sm">
          {t('remediationQuery.preview.tooMany', undefined, { max: preview.max })}
        </p>
      ) : preview.total === 0 ? (
        <p className="text-muted-foreground text-sm">{t('remediationQuery.preview.none')}</p>
      ) : (
        <>
          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-muted-foreground text-xs">
                {t('remediationQuery.preview.earliest')}
              </dt>
              <dd>{earliest ?? t('remediationQuery.preview.noDeadline')}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground text-xs">
                {t('remediationQuery.preview.suggested')}
              </dt>
              <dd>{suggestedName ?? t('remediationQuery.preview.noSuggestion')}</dd>
            </div>
          </dl>
          {stats && (
            <div className="grid gap-4 md:grid-cols-3">
              <Breakdown
                title={t('remediationQuery.preview.bySeverity')}
                rows={stats.severity}
                label={(r) => t(`remediationQuery.severity.${r.key}`, r.key)}
              />
              <Breakdown
                title={t('remediationQuery.preview.byAsset')}
                rows={stats.assets}
                label={(r) => r.name || r.key}
              />
              <Breakdown
                title={t('remediationQuery.preview.byOwner')}
                rows={stats.owners}
                label={ownerLabel}
              />
            </div>
          )}
          {stats && stats.sample.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <caption className="text-muted-foreground pb-1 text-left">
                  {t('remediationQuery.preview.sample', undefined, { count: stats.sample.length })}
                </caption>
                <thead>
                  <tr className="text-muted-foreground border-b text-left">
                    <th scope="col" className="py-1 pr-2 font-medium">
                      {t('remediationQuery.preview.colSeverity')}
                    </th>
                    <th scope="col" className="py-1 pr-2 font-medium">
                      {t('remediationQuery.preview.colFinding')}
                    </th>
                    <th scope="col" className="py-1 pr-2 font-medium">
                      {t('remediationQuery.preview.colAsset')}
                    </th>
                    <th scope="col" className="py-1 font-medium">
                      {t('remediationQuery.preview.colSla')}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {stats.sample.map((s) => (
                    <tr key={s.finding_id} className="border-b last:border-0">
                      <td className="py-1 pr-2">
                        <SeverityBadge severity={s.severity as Severity} />
                      </td>
                      <td className="max-w-64 truncate py-1 pr-2" title={s.title}>
                        {s.title}
                      </td>
                      <td className="max-w-40 truncate py-1 pr-2" title={s.asset_name}>
                        {s.asset_name}
                      </td>
                      <td className="py-1 whitespace-nowrap">
                        {formatDate(s.sla_deadline) ?? '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  )
}
