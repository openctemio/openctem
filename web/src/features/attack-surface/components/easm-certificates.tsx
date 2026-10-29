'use client'

/**
 * Attack surface > Certificates: the tenant's certificate assets as one
 * table (issued to, fingerprint, issuer, validity, status, detected), with
 * the expired and expiring-soon counts above it and a CSV export. Rows come
 * from the data-scoped read-layer endpoint; every value is scan output and is
 * shown as text.
 */

import { useCallback, useMemo, useState } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { Check, Copy, Download, ShieldX } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  DataTable,
  EmptyState,
  ErrorState,
  FilterSelect,
  MetricStrip,
  RelativeTime,
  StackedCell,
  TonePill,
  type MetricStripItem,
} from '@/features/shared'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { useTranslation } from '@/context/i18n-provider'
import { useSearchQuery } from '@/hooks/use-search-query'
import { useUrlFilter } from '@/hooks/use-url-param'
import { downloadCsv } from '@/hooks/use-csv-export'
import { formatDateSafe } from '@/lib/format-date'
import { copyToClipboard } from '@/lib/clipboard'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  fetchAllCertificates,
  useCertificateStats,
  useCertificates,
} from '../hooks/use-certificates'
import {
  CERTIFICATE_STATUSES,
  STATUS_LABEL,
  STATUS_TONE,
  certificatesCsv,
  isCertificateStatus,
  type CertificateFilters,
  type CertificateRow,
  type CertificateStatus,
} from '../lib/certificates'

const PAGE_SIZES = [20, 50, 100]

/** The full sha256 fingerprint, shortened for the cell and copyable. */
export function CopyableFingerprint({ value }: { value: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="text-muted-foreground">-</span>
  const copy = async () => {
    if (await copyToClipboard(value)) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } else {
      toast.error(t('attackSurface.certificates.copyFailed', 'Could not copy the fingerprint'))
    }
  }
  return (
    <span className="inline-flex items-center gap-1">
      <code className="font-mono text-xs" title={value}>
        {value.length > 20 ? `${value.slice(0, 16)}…` : value}
      </code>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="h-6 w-6"
        aria-label={t('attackSurface.certificates.copyFingerprint', 'Copy fingerprint')}
        onClick={copy}
      >
        {copied ? (
          <Check className="h-3.5 w-3.5" aria-hidden />
        ) : (
          <Copy className="h-3.5 w-3.5" aria-hidden />
        )}
      </Button>
    </span>
  )
}

/** The status of one certificate: tone icon plus text, never colour alone. */
export function CertificateStatusPill({ row }: { row: CertificateRow }) {
  const { t } = useTranslation()
  const days = row.days_to_expiry
  let detail: string | undefined
  if (row.status === 'expiring_soon' && days !== undefined) {
    detail = t('attackSurface.certificates.inDays', 'in {count} days', { count: Math.max(days, 0) })
  } else if (row.status === 'expired' && days !== undefined) {
    detail = t('attackSurface.certificates.daysAgo', '{count} days ago', { count: Math.abs(days) })
  }
  return (
    <TonePill
      tone={STATUS_TONE[row.status]}
      state={row.status}
      label={t(`attackSurface.certificates.status.${row.status}`, STATUS_LABEL[row.status])}
      detail={detail}
    />
  )
}

function useColumns(): ColumnDef<CertificateRow>[] {
  const { t } = useTranslation()
  return useMemo<ColumnDef<CertificateRow>[]>(
    () => [
      {
        id: 'subject_cn',
        header: t('attackSurface.certificates.col.issuedTo', 'Issued to'),
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[320px]"
            primary={
              <Link
                href={`/assets/${row.original.asset_id}`}
                className="font-medium hover:underline"
              >
                {row.original.subject_cn || row.original.name}
              </Link>
            }
            secondary={
              row.original.is_self_signed
                ? t('attackSurface.certificates.selfSigned', 'Self-signed')
                : row.original.is_wildcard
                  ? t('attackSurface.certificates.wildcard', 'Wildcard')
                  : undefined
            }
          />
        ),
      },
      {
        id: 'fingerprint',
        header: t('attackSurface.certificates.col.fingerprint', 'Fingerprint (SHA-256)'),
        enableSorting: false,
        cell: ({ row }) => <CopyableFingerprint value={row.original.fingerprint_sha256} />,
      },
      {
        id: 'issuer',
        header: t('attackSurface.certificates.col.issuer', 'Issuer'),
        enableSorting: false,
        cell: ({ row }) => (
          <StackedCell
            truncate
            className="max-w-[260px]"
            primary={row.original.issuer_cn || '-'}
            secondary={row.original.issuer_org || undefined}
          />
        ),
      },
      {
        id: 'not_before',
        header: t('attackSurface.certificates.col.issuedOn', 'Issued on'),
        enableSorting: false,
        cell: ({ row }) => formatDateSafe(row.original.not_before),
      },
      {
        id: 'not_after',
        header: t('attackSurface.certificates.col.expiresOn', 'Expires on'),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-col gap-1">
            <span>{formatDateSafe(row.original.not_after)}</span>
            <CertificateStatusPill row={row.original} />
          </div>
        ),
      },
      {
        id: 'first_seen',
        header: t('attackSurface.certificates.col.detected', 'Detected'),
        enableSorting: false,
        cell: ({ row }) => <RelativeTime date={row.original.first_seen} />,
      },
    ],
    [t]
  )
}

export function EASMCertificates() {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.AssetsRead)
  const [q, setQ] = useUrlFilter('q', '')
  const searchTerm = useSearchQuery(q).term
  const [statusParam, setStatus] = useUrlFilter('status', '')
  const status: CertificateStatus | undefined = isCertificateStatus(statusParam)
    ? statusParam
    : undefined
  const [pageParam, setPageParam] = useUrlFilter('page', '1')
  const [perPageParam, setPerPageParam] = useUrlFilter('per_page', '20')
  const pagination = useMemo(
    () => ({
      pageIndex: Math.max(0, (parseInt(pageParam, 10) || 1) - 1),
      pageSize: PAGE_SIZES.includes(parseInt(perPageParam, 10)) ? parseInt(perPageParam, 10) : 20,
    }),
    [pageParam, perPageParam]
  )
  const filters: CertificateFilters = useMemo(
    () => ({ q: searchTerm, status }),
    [searchTerm, status]
  )
  const list = useCertificates(filters, {
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  })
  const stats = useCertificateStats(filters)
  const columns = useColumns()
  const [exporting, setExporting] = useState(false)

  const statusLabel = useCallback(
    (s: CertificateStatus) => t(`attackSurface.certificates.status.${s}`, STATUS_LABEL[s]),
    [t]
  )
  const pickStatus = useCallback(
    (s: CertificateStatus | '') => {
      setStatus(s)
      setPageParam('1')
    },
    [setStatus, setPageParam]
  )

  const exportCsv = async () => {
    setExporting(true)
    try {
      const rows = await fetchAllCertificates(filters)
      downloadCsv(
        certificatesCsv(
          rows,
          [
            t('attackSurface.certificates.col.issuedTo', 'Issued to'),
            t('attackSurface.certificates.col.fingerprint', 'Fingerprint (SHA-256)'),
            t('attackSurface.certificates.csv.issuerCn', 'Issuer CN'),
            t('attackSurface.certificates.csv.issuerOrg', 'Issuer organization'),
            t('attackSurface.certificates.col.issuedOn', 'Issued on'),
            t('attackSurface.certificates.col.expiresOn', 'Expires on'),
            t('attackSurface.certificates.csv.status', 'Status'),
            t('attackSurface.certificates.csv.firstSeen', 'First detected'),
            t('attackSurface.certificates.csv.lastSeen', 'Last seen'),
          ],
          statusLabel
        ),
        'certificates.csv'
      )
    } catch {
      toast.error(t('attackSurface.certificates.exportFailed', 'Could not export. Try again.'))
    } finally {
      setExporting(false)
    }
  }

  if (!canRead) {
    return (
      <EmptyState
        icon={ShieldX}
        title={t('attackSurface.certificates.noAccess.title', 'Access denied')}
        description={t(
          'attackSurface.certificates.noAccess.description',
          "You don't have permission to view assets. Ask your administrator for access."
        )}
      />
    )
  }

  const s = stats.data
  const metrics: MetricStripItem[] = [
    {
      key: 'total',
      label: t('attackSurface.certificates.metric.total', 'Certificates'),
      value: s?.total ?? 0,
      active: !status,
      onClick: () => pickStatus(''),
    },
    {
      key: 'expired',
      label: t('attackSurface.certificates.metric.expired', 'Expired'),
      value: s?.expired ?? 0,
      tone: 'danger',
      active: status === 'expired',
      onClick: () => pickStatus(status === 'expired' ? '' : 'expired'),
    },
    {
      key: 'expiring_soon',
      label: t('attackSurface.certificates.metric.soon', 'Expiring in 30 days'),
      value: s?.expiring_soon ?? 0,
      tone: 'warning',
      active: status === 'expiring_soon',
      onClick: () => pickStatus(status === 'expiring_soon' ? '' : 'expiring_soon'),
    },
  ]

  const chips = status
    ? [
        <RemovableFilterChip
          key="status"
          text={t('attackSurface.certificates.chip.status', 'Status is {status}', {
            status: statusLabel(status),
          })}
          onRemove={() => pickStatus('')}
          removeLabel={t('attackSurface.certificates.chip.remove', 'Remove filter {filter}', {
            filter: statusLabel(status),
          })}
        />,
      ]
    : []

  return (
    <>
      <MetricStrip loading={stats.isLoading && !s} items={metrics} />
      <DataTable
        columns={columns}
        data={list.rows}
        getRowId={(c) => c.asset_id}
        showSearch={false}
        search={{
          value: q,
          onChange: (v: string) => {
            setQ(v)
            setPageParam('1')
          },
          placeholder: t(
            'attackSurface.certificates.search',
            'Search subject, issuer or fingerprint…'
          ),
        }}
        showColumnToggle={false}
        toolbarStart={
          <FilterSelect<CertificateStatus>
            label={t('attackSurface.certificates.filter.status', 'Status')}
            value={status ?? ''}
            options={CERTIFICATE_STATUSES.map((v) => ({ value: v, label: statusLabel(v) }))}
            onChange={(v) => pickStatus(v)}
          />
        }
        toolbarEnd={
          <Button variant="outline" size="sm" onClick={exportCsv} disabled={exporting}>
            <Download className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.certificates.export', 'Export CSV')}
          </Button>
        }
        toolbarBelow={
          chips.length > 0 ? (
            <FilterChipsRow
              label={t('attackSurface.certificates.activeFilters', 'Active filters')}
              chips={chips}
              end={t('attackSurface.certificates.count', '{count} certificates', {
                count: list.total,
              })}
            />
          ) : undefined
        }
        isLoading={list.isLoading && list.rows.length === 0}
        errorState={
          list.error && !list.isLoading ? (
            <ErrorState
              title={t('attackSurface.certificates.error', 'certificates')}
              error={list.error}
              onRetry={() => list.mutate()}
            />
          ) : undefined
        }
        manualPagination
        rowCount={list.total}
        pagination={pagination}
        onPaginationChange={(next) => {
          setPageParam(String(next.pageIndex + 1))
          setPerPageParam(String(next.pageSize))
        }}
        pageSizeOptions={PAGE_SIZES}
        emptyMessage={t('attackSurface.certificates.empty.title', 'No certificates yet')}
        emptyDescription={t(
          'attackSurface.certificates.empty.description',
          'Certificates appear here once a scan of your external assets reads their TLS certificates.'
        )}
      />
    </>
  )
}
