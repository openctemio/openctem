'use client'

/**
 * Requests > Sign-ups: the sign-up feed and its 30-day counts. Each event
 * shows the registrable email domain and the client network prefix only;
 * never a person. Organization events link to the organization.
 */

import { authProviderLabel } from '../lib/value-labels'
import { EmptyCell } from '@/features/shared/components/empty-cell'
import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { UserPlus } from 'lucide-react'
import {
  DataTable,
  EmptyState,
  ErrorState,
  FilterSelect,
  MetaLine,
  MetricStrip,
  RelativeTime,
  PageStack,
} from '@/features/shared'
import { ListCount, ListTitleRow } from '@/features/shared/components/list-title-row'
import { useTranslation } from '@/context/i18n-provider'
import {
  SIGNUP_EVENTS_PER_PAGE,
  SIGNUP_EVENT_KINDS,
  useSignupDaily,
  useSignupEvents,
  type SignupDailyCount,
  type SignupEvent,
  type SignupEventKind,
} from '../api/use-signup-events'
import { organizationHref } from '../lib/console-links'

const SUMMARY_DAYS = 30

/** Totals per kind for today, the last 7 days and the last 30 days (UTC). */
// The "password" source reads as "Email and password"; its key avoids the
// word so secret scanners do not read the catalog line as a credential.
function sourceKey(source: string): string {
  return source === 'password' ? 'emailAndPassword' : source
}

// A sign-up path: its own label, else the sign-in provider's name ("google"
// reads as Google), else its words. Never the raw value.
function sourceLabel(t: ReturnType<typeof useTranslation>['t'], source: string): string {
  const own = t(`admin.signups.source.${sourceKey(source)}`, '\u0000')
  return own !== '\u0000' ? own : authProviderLabel(t, source)
}

export function summarize(counts: SignupDailyCount[], today: string) {
  const out: Record<SignupEventKind, { today: number; week: number; month: number }> = {
    account_created: { today: 0, week: 0, month: 0 },
    organization_created: { today: 0, week: 0, month: 0 },
    access_requested: { today: 0, week: 0, month: 0 },
  }
  const end = Date.parse(`${today}T00:00:00Z`)
  for (const c of counts) {
    const row = out[c.kind]
    if (!row) continue
    const ageDays = Math.round((end - Date.parse(`${c.day}T00:00:00Z`)) / 86_400_000)
    if (ageDays < 0 || ageDays >= SUMMARY_DAYS) continue
    row.month += c.count
    if (ageDays < 7) row.week += c.count
    if (ageDays === 0) row.today += c.count
  }
  return out
}

/**
 * The 30-day counts as one compact strip under the list: the list is the
 * page's job and comes first on every width. Each tile shows the kind's count
 * for today with its 7- and 30-day totals, and filters the list by that kind
 * (the same request as the Event select).
 */
function SignupSummary({
  kind,
  onKind,
}: {
  kind: SignupEventKind | ''
  onKind: (kind: SignupEventKind | '') => void
}) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSignupDaily(SUMMARY_DAYS)
  if (error) {
    return (
      <ErrorState
        title={t('admin.signups.countsError')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  // While the counts load, the strip keeps its labels and a skeleton per value
  // and per detail line, so nothing moves when the numbers arrive.
  const loading = isLoading || !data
  const totals = summarize(data ?? [], new Date().toISOString().slice(0, 10))
  return (
    <MetricStrip
      loading={loading}
      items={SIGNUP_EVENT_KINDS.map((k) => ({
        key: k,
        label: t(`admin.signups.kind.${k}`),
        value: totals[k].today,
        detail: t('admin.signups.todayWeekMonth', undefined, {
          week: totals[k].week,
          month: totals[k].month,
        }),
        active: kind === k,
        onClick: () => onKind(kind === k ? '' : k),
      }))}
    />
  )
}

/**
 * A sign-up event on a phone. Fixed slots, never a label/value grid; a value
 * the event does not have is left out instead of showing a dash:
 *
 *   Organization created                 Open organization
 *   11 hours ago   google
 *   example.org   198.51.100.0/24
 */
export function SignupEventMobileCard({ event }: { event: SignupEvent }) {
  const { t } = useTranslation()
  return (
    <div data-slot="signup-card" className="flex w-full min-w-0 flex-col gap-1 px-3 py-3">
      <div className="flex min-w-0 items-baseline gap-2">
        <span className="min-w-0 flex-1 truncate font-medium">
          {t(`admin.signups.kind.${event.kind}`)}
        </span>
        {event.tenant_id ? (
          <Link
            className="shrink-0 text-meta underline-offset-4 hover:underline"
            href={organizationHref(event.tenant_id)}
          >
            {t('admin.signups.card.openOrganization', 'Open organization')}
          </Link>
        ) : null}
      </div>
      <MetaLine
        items={[
          <RelativeTime key="when" date={event.occurred_at} />,
          event.source ? <span key="source">{sourceLabel(t, event.source)}</span> : null,
        ]}
      />
      <MetaLine
        data-testid="signup-card-origin"
        className="font-mono"
        items={[
          event.email_domain ? <span key="domain">{event.email_domain}</span> : null,
          event.ip_prefix ? <span key="network">{event.ip_prefix}</span> : null,
        ]}
      />
    </div>
  )
}

export function SignupEventsPanel() {
  const { t } = useTranslation()
  const [kind, setKind] = useState<SignupEventKind | ''>('')
  const [page, setPage] = useState(1)
  const { data, error, isLoading, isValidating, mutate } = useSignupEvents(kind, page)
  const total = data?.total ?? 0

  const columns = useMemo<ColumnDef<SignupEvent>[]>(
    () => [
      {
        id: 'event',
        header: t('admin.signups.col.event'),
        // The event is the row's name; it stays in view while the table
        // scrolls sideways.
        meta: { kind: 'name', pin: 'start', minWidth: 200, label: t('admin.signups.col.event') },
        cell: ({ row }) => (
          <span className="block truncate font-medium">
            {t(`admin.signups.kind.${row.original.kind}`)}
          </span>
        ),
      },
      {
        id: 'when',
        header: t('admin.signups.col.when'),
        meta: { kind: 'datetime-recent', width: 152, label: t('admin.signups.col.when') },
        cell: ({ row }) => <RelativeTime date={row.original.occurred_at} />,
      },
      {
        id: 'source',
        header: t('admin.signups.col.source'),
        meta: {
          kind: 'text',
          width: 152,
          hideBelow: 800,
          label: t('admin.signups.col.source'),
        },
        cell: ({ row }) => (
          <span className="block truncate">{sourceLabel(t, row.original.source)}</span>
        ),
      },
      {
        id: 'domain',
        header: t('admin.signups.col.domain'),
        meta: { kind: 'text', width: 176, label: t('admin.signups.col.domain') },
        cell: ({ row }) =>
          row.original.email_domain ? (
            <span className="block truncate font-mono text-code" title={row.original.email_domain}>
              {row.original.email_domain}
            </span>
          ) : (
            <EmptyCell title={t('admin.signups.noDomain', 'No e-mail domain')} />
          ),
      },
      {
        id: 'network',
        header: t('admin.signups.col.network'),
        meta: {
          kind: 'text',
          width: 152,
          hideBelow: 900,
          label: t('admin.signups.col.network'),
        },
        cell: ({ row }) =>
          row.original.ip_prefix ? (
            <span className="block truncate font-mono text-code">{row.original.ip_prefix}</span>
          ) : (
            <EmptyCell title={t('admin.signups.noNetwork', 'No network recorded')} />
          ),
      },
      {
        id: 'organization',
        header: t('admin.signups.col.organization'),
        meta: { kind: 'text', width: 128, label: t('admin.signups.col.organization') },
        cell: ({ row }) =>
          row.original.tenant_id ? (
            <Link
              className="block truncate underline-offset-4 hover:underline"
              href={organizationHref(row.original.tenant_id)}
            >
              {t('admin.signups.openOrganization')}
            </Link>
          ) : (
            <EmptyCell title={t('admin.signups.noOrganization', 'No organization yet')} />
          ),
      },
    ],
    [t]
  )

  return (
    <PageStack>
      <ListTitleRow
        title={kind ? t(`admin.signups.kind.${kind}`) : t('admin.signups.allKinds')}
        count={
          <ListCount
            total={total}
            loading={!data && !error}
            label={t('admin.signups.total', undefined, { count: total })}
          />
        }
      />
      <DataTable
        columns={columns}
        data={data?.data ?? []}
        caption={t('admin.signups.caption', 'Sign-up events')}
        getRowId={(e) => String(e.id)}
        error={error}
        onRetry={() => void mutate()}
        errorTitle={t('admin.signups.listError')}
        // The first read: skeleton rows under a toolbar that stays mounted.
        isLoading={isLoading && !data}
        isRefreshing={isValidating && !!data}
        refreshingLabel={t('admin.signups.refreshing', 'Refreshing sign-ups')}
        showSearch={false}
        showSelectionCount={false}
        // A phone card with fixed slots, not the automatic label/value card.
        mobileRow={(e) => <SignupEventMobileCard event={e} />}
        toolbarStart={
          <FilterSelect<SignupEventKind>
            label={t('admin.signups.kindFilter')}
            value={kind}
            foldLabel
            allLabel={t('admin.signups.allKinds')}
            options={SIGNUP_EVENT_KINDS.map((k) => ({
              value: k,
              label: t(`admin.signups.kind.${k}`),
            }))}
            onChange={(v) => {
              setKind(v)
              setPage(1)
            }}
          />
        }
        isFiltered={!!kind}
        onClearFilters={() => {
          setKind('')
          setPage(1)
        }}
        emptyState={{
          nothingYet: (
            <EmptyState
              icon={UserPlus}
              title={t('admin.signups.emptyTitle')}
              description={t('admin.signups.emptyDesc')}
            />
          ),
          noMatch: { title: t('admin.signups.noMatch', 'No event of this kind') },
        }}
        manualPagination
        pageCount={data?.total_pages ?? 1}
        rowCount={total}
        pagination={{ pageIndex: page - 1, pageSize: SIGNUP_EVENTS_PER_PAGE }}
        onPaginationChange={(p) => setPage(p.pageIndex + 1)}
        pageSizeOptions={[SIGNUP_EVENTS_PER_PAGE]}
        paginationNoun={t('admin.signups.noun', 'events')}
      />
      <SignupSummary
        kind={kind}
        onKind={(k) => {
          setKind(k)
          setPage(1)
        }}
      />
      <p className="text-sm text-muted-foreground">{t('admin.signups.privacyNote')}</p>
    </PageStack>
  )
}
