'use client'

/**
 * Requests > Sign-ups: the sign-up feed and its 30-day counts. Each event
 * shows the registrable email domain and the client network prefix only;
 * never a person. Organization events link to the organization.
 */

import { useState } from 'react'
import Link from 'next/link'
import { UserPlus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { EmptyState, ErrorState, RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import {
  SIGNUP_EVENT_KINDS,
  useSignupDaily,
  useSignupEvents,
  type SignupDailyCount,
  type SignupEventKind,
} from '../api/use-signup-events'

const SUMMARY_DAYS = 30

/** Totals per kind for today, the last 7 days and the last 30 days (UTC). */
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
  const { data, error, isLoading, mutate } = useSignupEvents(kind, page)
  const rows = data?.data ?? []
  const totalPages = data?.total_pages ?? 1

  return (
    <div className="space-y-5">
      <SignupSummary />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted-foreground">
          {data ? t('admin.signups.total', undefined, { count: data.total }) : ''}
        </p>
        <Select
          value={kind || 'all'}
          onValueChange={(v) => {
            setKind(v === 'all' ? '' : (v as SignupEventKind))
            setPage(1)
          }}
        >
          <SelectTrigger className="w-56" aria-label={t('admin.signups.kindFilter')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('admin.signups.allKinds')}</SelectItem>
            {SIGNUP_EVENT_KINDS.map((k) => (
              <SelectItem key={k} value={k}>
                {t(`admin.signups.kind.${k}`)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {error ? (
        <ErrorState
          title={t('admin.signups.listError')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : isLoading && !data ? (
        <Skeleton className="h-40 w-full" />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={UserPlus}
          title={t('admin.signups.emptyTitle')}
          description={t('admin.signups.emptyDesc')}
        />
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('admin.signups.col.when')}</TableHead>
                  <TableHead>{t('admin.signups.col.event')}</TableHead>
                  <TableHead>{t('admin.signups.col.source')}</TableHead>
                  <TableHead>{t('admin.signups.col.domain')}</TableHead>
                  <TableHead>{t('admin.signups.col.network')}</TableHead>
                  <TableHead>{t('admin.signups.col.organization')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>
                      <RelativeTime date={e.occurred_at} />
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{t(`admin.signups.kind.${e.kind}`)}</Badge>
                    </TableCell>
                    <TableCell className="text-sm">
                      {t(`admin.signups.source.${e.source}`, e.source)}
                    </TableCell>
                    <TableCell className="font-mono text-sm">{e.email_domain || '—'}</TableCell>
                    <TableCell className="font-mono text-sm">{e.ip_prefix || '—'}</TableCell>
                    <TableCell className="text-sm">
                      {e.tenant_id ? (
                        <Link
                          className="underline-offset-4 hover:underline"
                          href={`/organizations/${encodeURIComponent(e.tenant_id)}`}
                        >
                          {t('admin.signups.openOrganization')}
                        </Link>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-end gap-2">
              <span className="text-sm text-muted-foreground">
                {t('admin.signups.page', undefined, { page, pages: totalPages })}
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
              >
                {t('admin.signups.prev')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
              >
                {t('admin.signups.next')}
              </Button>
            </div>
          )}
        </>
      )}
      <p className="text-sm text-muted-foreground">{t('admin.signups.privacyNote')}</p>
    </div>
  )
}
