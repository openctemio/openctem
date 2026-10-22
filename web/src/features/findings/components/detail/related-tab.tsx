'use client'

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Link2, Copy, Eye, ExternalLink, Repeat, Fingerprint } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { FindingDetail, RelatedFinding } from '../../types'
import { EmptyState, SeverityBadge, DataTable, DataTableColumnHeader } from '@/features/shared'
import { FindingStatusBadge } from '../finding-status-badge'
import { useTranslation } from '@/context/i18n-provider'

interface RelatedTabProps {
  finding: FindingDetail
}

interface RelatedFindingsTableProps {
  findings: RelatedFinding[]
  emptyMessage: string
  showSimilarity?: boolean
}

/** Most severe first when sorted descending. */
const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

function RelatedFindingsTable({
  findings,
  emptyMessage,
  showSimilarity = false,
}: RelatedFindingsTableProps) {
  const router = useRouter()
  const { t } = useTranslation()

  const columns = useMemo<ColumnDef<RelatedFinding>[]>(
    () => [
      {
        accessorKey: 'title',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.relatedTab.colFinding', 'Finding')}
          />
        ),
        cell: ({ row }) => (
          <div>
            <p className="font-medium">{row.original.title}</p>
            <p className="text-xs text-muted-foreground font-mono">{row.original.id}</p>
          </div>
        ),
      },
      {
        accessorKey: 'severity',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.relatedTab.colSeverity', 'Severity')}
          />
        ),
        sortingFn: (a, b) =>
          (SEVERITY_RANK[a.original.severity] ?? 0) - (SEVERITY_RANK[b.original.severity] ?? 0),
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.relatedTab.colStatus', 'Status')}
          />
        ),
        cell: ({ row }) => <FindingStatusBadge status={row.original.status} />,
      },
      {
        accessorKey: 'assetName',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('findings.relatedTab.colAsset', 'Asset')}
          />
        ),
        cell: ({ row }) => <span className="text-sm">{row.original.assetName}</span>,
      },
      ...(showSimilarity
        ? ([
            {
              accessorKey: 'similarity',
              header: ({ column }) => (
                <DataTableColumnHeader
                  column={column}
                  title={t('findings.relatedTab.colMatch', 'Match')}
                />
              ),
              cell: ({ row }) => {
                const similarity = row.original.similarity
                if (!similarity) return <span className="text-muted-foreground">-</span>
                return (
                  <span
                    className={cn(
                      'text-sm font-medium tabular-nums',
                      similarity >= 80
                        ? 'text-success'
                        : similarity >= 50
                          ? 'text-warning'
                          : 'text-muted-foreground'
                    )}
                  >
                    {similarity}%
                  </span>
                )
              },
            },
          ] as ColumnDef<RelatedFinding>[])
        : []),
      {
        id: 'actions',
        enableHiding: false,
        cell: ({ row }) => (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 w-7 p-0"
            aria-label={t('findings.relatedTab.open', 'Open {title}', {
              title: row.original.title,
            })}
            onClick={() => router.push(`/findings/${row.original.id}`)}
          >
            <ExternalLink className="h-3 w-3" />
          </Button>
        ),
      },
    ],
    [router, showSimilarity, t]
  )

  return (
    <DataTable
      columns={columns}
      data={findings}
      getRowId={(f) => f.id}
      showSearch={false}
      showColumnToggle={false}
      onRowClick={(f) => router.push(`/findings/${f.id}`)}
      emptyMessage={emptyMessage}
      emptyDescription=""
    />
  )
}

export function RelatedTab({ finding }: RelatedTabProps) {
  const { t } = useTranslation()
  const similarFindings = finding.similarFindings || []
  const linkedFindings = finding.linkedFindings || []
  const sameCveFindings = finding.cve ? finding.sameCveFindings || [] : []

  const totalRelated = similarFindings.length + linkedFindings.length + sameCveFindings.length

  // Check if there's any tracking info to show
  const hasTrackingInfo =
    finding.occurrenceCount !== undefined ||
    finding.duplicateCount !== undefined ||
    finding.correlationId

  // Empty state - show only when no related findings AND no tracking info
  if (totalRelated === 0 && !hasTrackingInfo) {
    return (
      <EmptyState
        icon={Link2}
        title={t('findings.relatedTab.emptyTitle', 'No Related Findings')}
        description={t(
          'findings.relatedTab.emptyDesc',
          'No similar or linked findings have been identified yet.'
        )}
        card={false}
      />
    )
  }

  return (
    <div className="space-y-6">
      {/* Tracking Info - occurrence, duplicates, correlation */}
      {hasTrackingInfo && (
        <div className="rounded-lg border bg-muted/30 p-4">
          <h3 className="text-sm font-semibold mb-3">
            {t('findings.relatedTab.trackingInfo', 'Tracking Info')}
          </h3>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {finding.occurrenceCount !== undefined && (
              <div className="flex items-center gap-3">
                <div className="bg-muted flex h-8 w-8 items-center justify-center rounded-full">
                  <Repeat className="h-4 w-4 text-info" />
                </div>
                <div>
                  <p className="text-lg font-bold">{finding.occurrenceCount}</p>
                  <p className="text-muted-foreground text-xs">
                    {t('findings.relatedTab.occurrences', 'Occurrences')}
                  </p>
                </div>
              </div>
            )}
            {finding.duplicateCount !== undefined && (
              <div className="flex items-center gap-3">
                <div className="bg-muted flex h-8 w-8 items-center justify-center rounded-full">
                  <Copy className="h-4 w-4 text-warning" />
                </div>
                <div>
                  <p className="text-lg font-bold">{finding.duplicateCount}</p>
                  <p className="text-muted-foreground text-xs">
                    {t('findings.relatedTab.duplicates', 'Duplicates')}
                  </p>
                </div>
              </div>
            )}
            {finding.correlationId && (
              <div className="flex items-center gap-3">
                <div className="bg-muted flex h-8 w-8 items-center justify-center rounded-full">
                  <Fingerprint className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p
                    className="text-xs font-mono truncate max-w-[150px]"
                    title={finding.correlationId}
                  >
                    {finding.correlationId}
                  </p>
                  <p className="text-muted-foreground text-xs">
                    {t('findings.relatedTab.correlationId', 'Correlation ID')}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Summary Stats - only show when there's related findings data */}
      {totalRelated > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {similarFindings.length > 0 && (
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <div className="bg-muted flex h-10 w-10 items-center justify-center rounded-full">
                <Eye className="h-5 w-5 text-info" />
              </div>
              <div>
                <p className="text-2xl font-bold">{similarFindings.length}</p>
                <p className="text-muted-foreground text-xs">
                  {t('findings.relatedTab.similar', 'Similar')}
                </p>
              </div>
            </div>
          )}
          {linkedFindings.length > 0 && (
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <div className="bg-muted flex h-10 w-10 items-center justify-center rounded-full">
                <Link2 className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{linkedFindings.length}</p>
                <p className="text-muted-foreground text-xs">
                  {t('findings.relatedTab.linked', 'Linked')}
                </p>
              </div>
            </div>
          )}
          {finding.cve && sameCveFindings.length > 0 && (
            <div className="flex items-center gap-3 rounded-lg border p-4">
              <div className="bg-muted flex h-10 w-10 items-center justify-center rounded-full">
                <Copy className="h-5 w-5 text-warning" />
              </div>
              <div>
                <p className="text-2xl font-bold">{sameCveFindings.length}</p>
                <p className="text-muted-foreground text-xs">
                  {t('findings.relatedTab.sameCve', 'Same CVE')}
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Similar Findings - only show section if has data */}
      {similarFindings.length > 0 && (
        <div>
          <div className="mb-3">
            <h3 className="flex items-center gap-2 font-semibold">
              <Eye className="h-4 w-4 text-info" />
              {t('findings.relatedTab.similarTitle', 'Similar Findings')}
            </h3>
            <p className="text-muted-foreground text-sm">
              {t(
                'findings.relatedTab.similarDesc',
                'Findings with similar characteristics detected by AI'
              )}
            </p>
          </div>
          <RelatedFindingsTable
            findings={similarFindings}
            emptyMessage={t('findings.relatedTab.similarEmpty', 'No similar findings detected')}
            showSimilarity
          />
        </div>
      )}

      {/* Linked Findings - only show section if has data */}
      {linkedFindings.length > 0 && (
        <>
          {similarFindings.length > 0 && <Separator />}
          <div>
            <div className="mb-3">
              <h3 className="flex items-center gap-2 font-semibold">
                <Link2 className="h-4 w-4 text-primary" />
                {t('findings.relatedTab.linkedTitle', 'Linked Findings')}
              </h3>
              <p className="text-muted-foreground text-sm">
                {t('findings.relatedTab.linkedDesc', 'Manually linked related findings')}
              </p>
            </div>
            <RelatedFindingsTable
              findings={linkedFindings}
              emptyMessage={t('findings.relatedTab.linkedEmpty', 'No linked findings')}
            />
          </div>
        </>
      )}

      {/* Same CVE - only show section if has CVE and data */}
      {finding.cve && sameCveFindings.length > 0 && (
        <>
          {(similarFindings.length > 0 || linkedFindings.length > 0) && <Separator />}
          <div>
            <div className="mb-3">
              <h3 className="flex items-center gap-2 font-semibold">
                <Copy className="h-4 w-4 text-warning" />
                {t('findings.relatedTab.sameCveTitle', 'Same CVE ({cve})', { cve: finding.cve })}
              </h3>
              <p className="text-muted-foreground text-sm">
                {t(
                  'findings.relatedTab.sameCveDesc',
                  'Other findings with the same CVE identifier'
                )}
              </p>
            </div>
            <RelatedFindingsTable
              findings={sameCveFindings}
              emptyMessage={t(
                'findings.relatedTab.sameCveEmpty',
                'No other findings with this CVE'
              )}
            />
          </div>
        </>
      )}
    </div>
  )
}
