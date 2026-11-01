'use client'

import { useMemo } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import Link from '@/components/link'
import { Radar, RotateCcw, ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react'
import {
  PageHeader,
  PageStack,
  DataTable,
  DataTableColumnHeader,
  EmptyState,
} from '@/features/shared'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useRecentDetections, iocTypeLabel, type IOCMatch, type IOCType } from '../api/use-iocs-api'
import { useTranslation } from '@/context/i18n-provider'

// Detections view — the tenant-wide Detect/Respond feed. Each row is a runtime
// detection (from an EDR/XDR/SIEM forwarder via /telemetry-events) that matched
// a known indicator; `reopened` shows whether it auto-reopened the source
// finding. Backed by GET /api/v1/iocs/matches.
export function DetectionsPanel() {
  const { t } = useTranslation()
  const { data, isLoading, error, mutate } = useRecentDetections(100)
  const rows = useMemo(() => data?.items ?? [], [data])

  const columns = useMemo<ColumnDef<IOCMatch>[]>(
    () => [
      {
        accessorKey: 'ioc_type',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatIntel.detections.col.indicator', 'Indicator')}
          />
        ),
        cell: ({ row }) => {
          const iocType = row.original.ioc_type as IOCType | undefined
          return (
            <div className="flex items-center gap-2">
              {iocType && <Badge variant="outline">{iocTypeLabel(t, iocType)}</Badge>}
              <span className="font-mono text-sm">{row.original.ioc_value ?? '—'}</span>
            </div>
          )
        },
      },
      {
        accessorKey: 'matched_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatIntel.detections.col.detected', 'Detected')}
          />
        ),
        cell: ({ row }) => (
          <span className="whitespace-nowrap tabular-nums">
            {new Date(row.original.matched_at).toLocaleString()}
          </span>
        ),
      },
      {
        accessorKey: 'reopened',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatIntel.detections.col.response', 'Response')}
          />
        ),
        cell: ({ row }) =>
          row.original.reopened ? (
            <Badge variant="destructive" className="gap-1">
              <RotateCcw className="size-3" />{' '}
              {t('threatIntel.detections.reopened', 'Finding reopened')}
            </Badge>
          ) : (
            <Badge variant="secondary" className="gap-1">
              <ShieldCheck className="size-3" /> {t('threatIntel.detections.logged', 'Logged')}
            </Badge>
          ),
      },
      {
        accessorKey: 'finding_title',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('threatIntel.detections.col.finding', 'Finding')}
          />
        ),
        cell: ({ row }) => {
          const { finding_id, finding_title } = row.original
          if (!finding_id) return <span className="text-muted-foreground">—</span>
          return (
            <Link
              href={`/findings/${finding_id}`}
              className="text-primary max-w-xs truncate hover:underline"
            >
              {finding_title || finding_id}
            </Link>
          )
        },
      },
    ],
    [t]
  )

  return (
    <PageStack>
      <PageHeader
        title={t('threatIntel.detections.title', 'Detections')}
        description={t(
          'threatIntel.detections.description',
          'Runtime detections from your EDR, XDR or SIEM that matched a known indicator; a match on a resolved finding reopens it.'
        )}
      />

      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : error ? (
        // A failed read is not "no detections" — say so, and offer a retry.
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>
            {t('threatIntel.detections.loadFailed', 'Failed to load detections')}
          </AlertTitle>
          <AlertDescription>
            <p>
              {getErrorMessage(error, t('threatIntel.detections.tryAgain', 'Please try again.'))}
            </p>
            <Button variant="outline" size="sm" className="mt-2" onClick={() => mutate()}>
              <RefreshCw className="me-2 h-4 w-4" />
              {t('threatIntel.detections.retry', 'Retry')}
            </Button>
          </AlertDescription>
        </Alert>
      ) : rows.length === 0 ? (
        <EmptyState
          icon={Radar}
          title={t('threatIntel.detections.emptyTitle', 'No detections yet')}
          description={t(
            'threatIntel.detections.emptyDescription',
            'Detections appear here when a collector sensor forwards a runtime event that matches an indicator in your catalogue.'
          )}
        />
      ) : (
        <DataTable
          columns={columns}
          data={rows}
          searchPlaceholder={t('threatIntel.detections.search', 'Search detections…')}
        />
      )}
    </PageStack>
  )
}
