'use client'

/**
 * One open support session (api RFC-063): a coloured frame that says the view
 * is read-only and when it ends, then Overview / Findings / Assets tabs for
 * the scopes the organization granted. The server checks every read (live
 * grant, the caller's session bound to this console session, granted scope)
 * and audits it before answering; this view only reflects that. When a read
 * says the access ended (SUPPORT_GRANT_REQUIRED) the view closes.
 */

import { useEffect, useState } from 'react'
import { Loader2, Search, ShieldAlert } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import {
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSheet,
  ErrorState,
  SeverityBadge,
} from '@/features/shared'
import type { Severity } from '@/features/shared/types/common.types'
import { useDebounce } from '@/hooks/use-debounce'
import { SEVERITY_LEVELS } from '@/lib/severity'
import { formatSupportTime } from '@/features/support-access/lib/format'

import {
  isSupportAccessEnded,
  SUPPORT_PAGE_SIZE,
  useSupportAsset,
  useSupportAssets,
  useSupportFinding,
  useSupportFindings,
  useSupportOverview,
} from '../api/use-admin-support'

export interface SupportSessionState {
  id: string
  grantId: string
  tenantName: string
  scopes: string[]
  expiresAt: string
}

const SEVERITIES = SEVERITY_LEVELS
const FINDING_STATUSES = ['open', 'all', 'resolved', 'false_positive', 'accepted'] as const
const ASSET_STATUSES = ['all', 'active', 'stale', 'inactive', 'archived'] as const
const ALL = 'all'

/** Leaves the session view when a read says the access ended. */
function useEndOnRevoked(error: unknown, onEnded: () => void) {
  useEffect(() => {
    if (isSupportAccessEnded(error)) onEnded()
  }, [error, onEnded])
}

function ReadError({ error }: { error: unknown }) {
  const { t } = useTranslation()
  return (
    <ErrorState
      title={t('admin.support.readFailed', 'This data could not be read')}
      error={error}
    />
  )
}

function asSeverity(v: string | undefined): Severity {
  return (SEVERITIES as readonly string[]).includes(v ?? '') ? (v as Severity) : 'none'
}

function Pager({
  page,
  total,
  onPage,
}: {
  page: number
  total: number
  onPage: (p: number) => void
}) {
  const { t } = useTranslation()
  const pages = Math.max(1, Math.ceil(total / SUPPORT_PAGE_SIZE))
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 pt-3 text-sm text-muted-foreground">
      <span>
        {t('admin.support.pageOf', 'Page {page} of {pages} · {total} total', {
          page,
          pages,
          total,
        })}
      </span>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          {t('admin.support.prev', 'Previous')}
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={page >= pages}
          onClick={() => onPage(page + 1)}
        >
          {t('admin.support.next', 'Next')}
        </Button>
      </div>
    </div>
  )
}

function SearchBox({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation()
  return (
    <div className="relative w-full sm:w-64">
      <Search
        className="pointer-events-none absolute start-2.5 top-2.5 size-4 text-muted-foreground"
        aria-hidden="true"
      />
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={t('admin.support.search', 'Search by name')}
        aria-label={t('admin.support.search', 'Search by name')}
        className="ps-8"
      />
    </div>
  )
}

function OverviewTab({ session, onEnded }: { session: SupportSessionState; onEnded: () => void }) {
  const { t } = useTranslation()
  const { data, error, isLoading } = useSupportOverview(session.id)
  useEndOnRevoked(error, onEnded)
  if (error) return <ReadError error={error} />
  if (isLoading || !data) return <Skeleton className="h-32 w-full" />
  const bySev = data.open_findings_by_severity ?? {}
  return (
    <div className="space-y-4">
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-md border p-3">
          <dt className="text-xs text-muted-foreground">
            {t('admin.support.organization', 'Organization')}
          </dt>
          <dd className="font-medium break-words">{data.tenant_name}</dd>
        </div>
        {/* A part the grant does not open is absent, not zero. */}
        {data.asset_count !== undefined && (
          <div className="rounded-md border p-3">
            <dt className="text-xs text-muted-foreground">{t('admin.support.assets', 'Assets')}</dt>
            <dd className="text-xl font-semibold tabular-nums">{data.asset_count}</dd>
          </div>
        )}
        {data.open_finding_count !== undefined && (
          <div className="rounded-md border p-3">
            <dt className="text-xs text-muted-foreground">
              {t('admin.support.openFindings', 'Open findings')}
            </dt>
            <dd className="text-xl font-semibold tabular-nums">{data.open_finding_count}</dd>
          </div>
        )}
      </dl>
      {data.open_finding_count !== undefined && (
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((sev) => (
            <span key={sev} className="flex items-center gap-1.5 text-sm">
              <SeverityBadge severity={sev} />
              <span className="tabular-nums">{bySev[sev] ?? 0}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingsTab({ session, onEnded }: { session: SupportSessionState; onEnded: () => void }) {
  const { t, locale } = useTranslation()
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState<string>(ALL)
  const [status, setStatus] = useState<string>('open')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<string | null>(null)
  const debounced = useDebounce(search, 300)
  const { data, error, isLoading } = useSupportFindings(session.id, {
    search: debounced,
    severity: severity === ALL ? undefined : severity,
    status: status === ALL ? '' : status,
    page,
  })
  useEndOnRevoked(error, onEnded)
  const rows = data?.data ?? []

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        <SearchBox
          value={search}
          onChange={(v) => {
            setSearch(v)
            setPage(1)
          }}
        />
        <Select
          value={severity}
          onValueChange={(v) => {
            setSeverity(v)
            setPage(1)
          }}
        >
          <SelectTrigger
            className="w-full sm:w-40"
            aria-label={t('admin.support.severity', 'Severity')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>
              {t('admin.support.allSeverities', 'All severities')}
            </SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {t(`admin.support.severity.${s}`, s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={status}
          onValueChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        >
          <SelectTrigger
            className="w-full sm:w-44"
            aria-label={t('admin.support.status', 'Status')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {FINDING_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {t(`admin.support.findingStatus.${s}`, s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {error ? (
        <ReadError error={error} />
      ) : isLoading && !data ? (
        <Skeleton className="h-40 w-full" />
      ) : rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted-foreground">
          {t('admin.support.noFindings', 'No findings match.')}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.support.title', 'Title')}</TableHead>
                <TableHead>{t('admin.support.severity', 'Severity')}</TableHead>
                <TableHead>{t('admin.support.status', 'Status')}</TableHead>
                <TableHead>{t('admin.support.asset', 'Asset')}</TableHead>
                <TableHead>{t('admin.support.lastSeen', 'Last seen')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((f) => (
                <TableRow
                  key={f.id}
                  data-testid="support-finding-row"
                  className="cursor-pointer"
                  onClick={() => setSelected(f.id ?? null)}
                >
                  <TableCell className="max-w-80">
                    <button
                      type="button"
                      className="block w-full truncate text-start font-medium hover:underline"
                      onClick={(e) => {
                        e.stopPropagation()
                        setSelected(f.id ?? null)
                      }}
                    >
                      {f.title}
                    </button>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={asSeverity(f.severity)} />
                  </TableCell>
                  <TableCell className="whitespace-nowrap">{f.status}</TableCell>
                  <TableCell className="max-w-48 truncate">{f.asset_name || '—'}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {formatSupportTime(f.last_seen_at, locale)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {data && <Pager page={page} total={data.total ?? 0} onPage={setPage} />}
      <FindingDetail
        sessionId={session.id}
        id={selected}
        onClose={() => setSelected(null)}
        onEnded={onEnded}
      />
    </div>
  )
}

function FindingDetail({
  sessionId,
  id,
  onClose,
  onEnded,
}: {
  sessionId: string
  id: string | null
  onClose: () => void
  onEnded: () => void
}) {
  const { t, locale } = useTranslation()
  const { data, error } = useSupportFinding(sessionId, id)
  useEndOnRevoked(error, onEnded)
  return (
    <DetailSheet
      open={id !== null}
      onOpenChange={(o) => !o && onClose()}
      width="lg"
      header={
        <DetailHeader
          title={data?.title ?? t('admin.support.finding', 'Finding')}
          badges={data && <SeverityBadge severity={asSeverity(data.severity)} />}
          meta={data ? [data.status ?? '', data.tool_name ?? ''].filter(Boolean) : []}
          onClose={onClose}
        />
      }
    >
      {error ? (
        <ReadError error={error} />
      ) : !data ? (
        <Skeleton className="h-48 w-full" />
      ) : (
        <DetailFieldGrid>
          <DetailField label={t('admin.support.source', 'Source')}>
            {data.source || '—'}
          </DetailField>
          <DetailField label={t('admin.support.rule', 'Rule')}>
            <code className="text-xs break-all">{data.rule_id || '—'}</code>
          </DetailField>
          <DetailField label={t('admin.support.cve', 'CVE')}>{data.cve_id || '—'}</DetailField>
          <DetailField label={t('admin.support.cwe', 'CWE')}>
            {(data.cwe_ids ?? []).join(', ') || '—'}
          </DetailField>
          <DetailField label={t('admin.support.asset', 'Asset')}>
            {data.asset_name
              ? `${data.asset_name}${data.asset_type ? ` (${data.asset_type})` : ''}`
              : '—'}
          </DetailField>
          <DetailField label={t('admin.support.sla', 'SLA')}>{data.sla_status || '—'}</DetailField>
          <DetailField label={t('admin.support.location', 'Location')} full>
            <code className="text-xs break-all">
              {data.file_path
                ? `${data.file_path}${data.start_line ? `:${data.start_line}` : ''}`
                : '—'}
            </code>
          </DetailField>
          <DetailField label={t('admin.support.firstSeen', 'First seen')}>
            {formatSupportTime(data.first_detected_at, locale)}
          </DetailField>
          <DetailField label={t('admin.support.lastSeen', 'Last seen')}>
            {formatSupportTime(data.last_seen_at, locale)}
          </DetailField>
        </DetailFieldGrid>
      )}
    </DetailSheet>
  )
}

function AssetsTab({ session, onEnded }: { session: SupportSessionState; onEnded: () => void }) {
  const { t, locale } = useTranslation()
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<string>(ALL)
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<string | null>(null)
  const debounced = useDebounce(search, 300)
  const { data, error, isLoading } = useSupportAssets(session.id, {
    search: debounced,
    status: status === ALL ? '' : status,
    page,
  })
  useEndOnRevoked(error, onEnded)
  const rows = data?.data ?? []

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        <SearchBox
          value={search}
          onChange={(v) => {
            setSearch(v)
            setPage(1)
          }}
        />
        <Select
          value={status}
          onValueChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        >
          <SelectTrigger
            className="w-full sm:w-44"
            aria-label={t('admin.support.status', 'Status')}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ASSET_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {t(`admin.support.assetStatus.${s}`, s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {error ? (
        <ReadError error={error} />
      ) : isLoading && !data ? (
        <Skeleton className="h-40 w-full" />
      ) : rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted-foreground">
          {t('admin.support.noAssets', 'No assets match.')}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.support.name', 'Name')}</TableHead>
                <TableHead>{t('admin.support.type', 'Type')}</TableHead>
                <TableHead>{t('admin.support.criticality', 'Criticality')}</TableHead>
                <TableHead className="text-end">{t('admin.support.risk', 'Risk')}</TableHead>
                <TableHead className="text-end">
                  {t('admin.support.findings', 'Findings')}
                </TableHead>
                <TableHead>{t('admin.support.lastSeen', 'Last seen')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((a) => (
                <TableRow
                  key={a.id}
                  data-testid="support-asset-row"
                  className="cursor-pointer"
                  onClick={() => setSelected(a.id ?? null)}
                >
                  <TableCell className="max-w-72">
                    <button
                      type="button"
                      className="block w-full truncate text-start font-medium hover:underline"
                      onClick={(e) => {
                        e.stopPropagation()
                        setSelected(a.id ?? null)
                      }}
                    >
                      {a.name}
                    </button>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">{a.type}</TableCell>
                  <TableCell className="whitespace-nowrap">{a.criticality || '—'}</TableCell>
                  <TableCell className="text-end tabular-nums">{a.risk_score ?? 0}</TableCell>
                  <TableCell className="text-end tabular-nums">{a.finding_count ?? 0}</TableCell>
                  <TableCell className="whitespace-nowrap">
                    {formatSupportTime(a.last_seen, locale)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {data && <Pager page={page} total={data.total ?? 0} onPage={setPage} />}
      <AssetDetail
        sessionId={session.id}
        id={selected}
        onClose={() => setSelected(null)}
        onEnded={onEnded}
      />
    </div>
  )
}

function AssetDetail({
  sessionId,
  id,
  onClose,
  onEnded,
}: {
  sessionId: string
  id: string | null
  onClose: () => void
  onEnded: () => void
}) {
  const { t, locale } = useTranslation()
  const { data, error } = useSupportAsset(sessionId, id)
  useEndOnRevoked(error, onEnded)
  return (
    <DetailSheet
      open={id !== null}
      onOpenChange={(o) => !o && onClose()}
      width="lg"
      header={
        <DetailHeader
          title={data?.name ?? t('admin.support.assetTitle', 'Asset')}
          meta={data ? [data.type ?? '', data.status ?? ''].filter(Boolean) : []}
          onClose={onClose}
        />
      }
    >
      {error ? (
        <ReadError error={error} />
      ) : !data ? (
        <Skeleton className="h-48 w-full" />
      ) : (
        <DetailFieldGrid>
          <DetailField label={t('admin.support.criticality', 'Criticality')}>
            {data.criticality || '—'}
          </DetailField>
          <DetailField label={t('admin.support.exposure', 'Exposure')}>
            {data.exposure || '—'}
          </DetailField>
          <DetailField label={t('admin.support.risk', 'Risk')}>
            <span className="tabular-nums">{data.risk_score ?? 0}</span>
          </DetailField>
          <DetailField label={t('admin.support.findings', 'Findings')}>
            <span className="tabular-nums">{data.finding_count ?? 0}</span>
          </DetailField>
          <DetailField label={t('admin.support.firstSeen', 'First seen')}>
            {formatSupportTime(data.first_seen, locale)}
          </DetailField>
          <DetailField label={t('admin.support.lastSeen', 'Last seen')}>
            {formatSupportTime(data.last_seen, locale)}
          </DetailField>
        </DetailFieldGrid>
      )}
    </DetailSheet>
  )
}

export function SupportSessionView({
  session,
  onEnd,
  onEnded,
  ending,
}: {
  session: SupportSessionState
  /** The administrator ends the session. */
  onEnd: () => void
  /** The server says the access ended (or it ran out). */
  onEnded: () => void
  ending?: boolean
}) {
  const { t, locale } = useTranslation()
  const hasFindings = session.scopes.includes('findings')
  const hasAssets = session.scopes.includes('assets')

  // Close the view when the window runs out; the server refuses reads anyway.
  useEffect(() => {
    const ms = new Date(session.expiresAt).getTime() - Date.now()
    if (!Number.isFinite(ms)) return
    const timer = window.setTimeout(onEnded, Math.max(0, Math.min(ms, 2_147_000_000)))
    return () => window.clearTimeout(timer)
  }, [session.expiresAt, onEnded])

  return (
    <section
      data-testid="support-session-frame"
      aria-label={t('admin.support.frameLabel', 'Support session')}
      className="overflow-hidden rounded-lg border-2 border-warning"
    >
      <div className="sticky top-0 z-10 flex flex-col gap-2 bg-warning/15 px-4 py-3 backdrop-blur sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-start gap-2">
          <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warning" aria-hidden="true" />
          <div className="min-w-0">
            <p className="font-semibold break-words">
              {t('admin.support.frame', 'Support session — read-only — ends {time}', {
                time: formatSupportTime(session.expiresAt, locale),
              })}
            </p>
            <p className="text-sm break-words text-muted-foreground">
              {t(
                'admin.support.frameHint',
                '{org}: every page you open is recorded in the organization’s audit log.',
                { org: session.tenantName }
              )}
            </p>
          </div>
        </div>
        <Button
          variant="destructive"
          size="sm"
          className="shrink-0"
          onClick={onEnd}
          disabled={ending}
        >
          {ending && <Loader2 className="size-4 animate-spin" aria-hidden="true" />}
          {t('admin.support.end', 'End session')}
        </Button>
      </div>
      <div className="p-4">
        <Tabs defaultValue="overview">
          <TabsList className="max-w-full overflow-x-auto">
            <TabsTrigger value="overview">
              {t('admin.support.tab.overview', 'Overview')}
            </TabsTrigger>
            {hasFindings && (
              <TabsTrigger value="findings">
                {t('admin.support.tab.findings', 'Findings')}
              </TabsTrigger>
            )}
            {hasAssets && (
              <TabsTrigger value="assets">{t('admin.support.tab.assets', 'Assets')}</TabsTrigger>
            )}
          </TabsList>
          <TabsContent value="overview" className="pt-4">
            <OverviewTab session={session} onEnded={onEnded} />
            <div className="mt-4 flex flex-wrap gap-1.5">
              {session.scopes.map((s) => (
                <Badge key={s} variant="outline">
                  {t(`admin.support.scope.${s}`, s)}
                </Badge>
              ))}
            </div>
          </TabsContent>
          {hasFindings && (
            <TabsContent value="findings" className="pt-4">
              <FindingsTab session={session} onEnded={onEnded} />
            </TabsContent>
          )}
          {hasAssets && (
            <TabsContent value="assets" className="pt-4">
              <AssetsTab session={session} onEnded={onEnded} />
            </TabsContent>
          )}
        </Tabs>
      </div>
    </section>
  )
}
