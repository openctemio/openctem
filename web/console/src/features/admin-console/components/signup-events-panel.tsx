'use client'

/**
 * Requests > Sign-ups: the sign-up feed and its 30-day counts. Each event
 * shows the registrable email domain and the client network prefix only;
 * never a person. Organization events link to the organization.
 */

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { UserPlus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DataTable,
  EmptyState,
  ErrorState,
  FilterSelect,
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

function SignupSummary() {
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
  if (isLoading || !data) return <Skeleton className="h-28 w-full" />
  const totals = summarize(data, new Date().toISOString().slice(0, 10))
  return (
    <div className="grid gap-4 sm:grid-cols-3">
      {SIGNUP_EVENT_KINDS.map((kind) => (
        <Card key={kind}>
          <CardHeader className="pb-2">
            <CardDescription>{t(`admin.signups.kind.${kind}`)}</CardDescription>
            <CardTitle className="text-2xl tabular-nums">{totals[kind].today}</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {t('admin.signups.todayWeekMonth', undefined, {
              week: totals[kind].week,
              month: totals[kind].month,
            })}
          </CardContent>
        </Card>
      ))}
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
          <Badge variant="outline">{t(`admin.signups.kind.${row.original.kind}`)}</Badge>
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
        meta: { kind: 'text', width: 184, label: t('admin.signups.col.source') },
        cell: ({ row }) => (
          <span className="block truncate">
            {t(`admin.signups.source.${sourceKey(row.original.source)}`, row.original.source)}
          </span>
        ),
      },
      {
        id: 'domain',
        header: t('admin.signups.col.domain'),
        meta: { kind: 'text', width: 200, label: t('admin.signups.col.domain') },
        cell: ({ row }) => (
          <span className="block truncate font-mono text-xs" title={row.original.email_domain}>
            {row.original.email_domain || '—'}
          </span>
        ),
      },
      {
        id: 'network',
        header: t('admin.signups.col.network'),
        meta: {
          kind: 'text',
          width: 168,
          hideBelow: 900,
          label: t('admin.signups.col.network'),
        },
        cell: ({ row }) => (
          <span className="block truncate font-mono text-xs">{row.original.ip_prefix || '—'}</span>
        ),
      },
      {
        id: 'organization',
        header: t('admin.signups.col.organization'),
        meta: { kind: 'text', width: 176, label: t('admin.signups.col.organization') },
        cell: ({ row }) =>
          row.original.tenant_id ? (
            <Link
              className="block truncate underline-offset-4 hover:underline"
              href={organizationHref(row.original.tenant_id)}
            >
              {t('admin.signups.openOrganization')}
            </Link>
          ) : (
            '—'
          ),
      },
    ],
    [t]
  )

  return (
    <PageStack>
      <SignupSummary />
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
        mobileCards
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
      <p className="text-sm text-muted-foreground">{t('admin.signups.privacyNote')}</p>
    </PageStack>
  )
}
