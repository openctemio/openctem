'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  EmptyState,
  PageHeader,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Can, Permission } from '@/lib/permissions'
import { GitMerge, Check, X, CopyCheck } from 'lucide-react'
import { toast } from 'sonner'
import {
  useDedupReviews,
  approveDedupReview,
  rejectDedupReview,
  type DedupReview,
} from '../api/use-asset-dedup'
import { dedupReasonLabel, describeEvidence } from '../lib/asset-identity'
import { AssetAttentionTabs, AssetsSectionTabs } from './assets-section-tabs'

// DedupReviewPage surfaces the identity/dedup flow that was previously
// invisible: the correlator enqueues a pending review when several assets share
// identity, and an operator approves (merge) or rejects (keep separate). The
// backend + hooks already existed; this is the missing operator UI.
export function DedupReviewPage() {
  const { data, isLoading, error, mutate } = useDedupReviews()
  const [busyId, setBusyId] = useState<string | null>(null)
  // Merging deletes the duplicates, so it asks first; keeping them separate does not.
  const [pendingMerge, setPendingMerge] = useState<DedupReview | null>(null)
  const { t } = useTranslation()

  const reviews = data?.data ?? []

  // useCallback so the columns memo can depend on it; mutate is stable (SWR).
  const act = useCallback(
    async (id: string, action: 'approve' | 'reject') => {
      setBusyId(id)
      try {
        if (action === 'approve') {
          await approveDedupReview(id)
          setPendingMerge(null)
          toast.success(t('assets.dedup.merged', 'Duplicates merged'))
        } else {
          await rejectDedupReview(id)
          toast.success(t('assets.dedup.kept', 'Kept as separate assets'))
        }
        await mutate()
      } catch {
        toast.error(
          action === 'approve'
            ? t('assets.dedup.approveFailed', 'Failed to approve review')
            : t('assets.dedup.rejectFailed', 'Failed to reject review')
        )
      } finally {
        setBusyId(null)
      }
    },
    [mutate, t]
  )

  const columns = useMemo<ColumnDef<DedupReview>[]>(
    () => [
      {
        accessorKey: 'normalized_name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.identity', 'Identity')} />
        ),
        cell: ({ row }) => (
          <div>
            <div className="font-medium">{row.original.normalized_name}</div>
            <Badge variant="outline" className="mt-1">
              {row.original.asset_type}
            </Badge>
          </div>
        ),
      },
      {
        id: 'reason',
        accessorFn: (r) => dedupReasonLabel(r.reason),
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.reason', 'Reason')} />
        ),
        cell: ({ row }) => {
          const evidence = describeEvidence(row.original.evidence)
          return (
            <div className="min-w-0">
              <div className="text-sm">{dedupReasonLabel(row.original.reason)}</div>
              {evidence && (
                <div className="mt-0.5 break-words text-xs text-muted-foreground">{evidence}</div>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'keep_asset_name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.keep', 'Keep')} />
        ),
        cell: ({ row }) => (
          <StackedCell
            primary={row.original.keep_asset_name}
            secondary={
              row.original.keep_finding_count === 1
                ? t('assets.dedup.findingOne', '1 finding')
                : t('assets.dedup.findingMany', '{count} findings', {
                    count: row.original.keep_finding_count,
                  })
            }
          />
        ),
      },
      {
        id: 'merge',
        header: t('assets.dedup.mergeInto', 'Merge into it'),
        enableSorting: false,
        cell: ({ row }) => (
          <div>
            <div className="flex flex-wrap gap-1">
              {row.original.merge_asset_names.map((name, i) => (
                <Badge key={i} variant="secondary">
                  {name}
                </Badge>
              ))}
            </div>
            <div className="mt-1 text-xs text-muted-foreground">
              {row.original.merge_asset_ids.length === 1
                ? t('assets.dedup.assetOne', '1 asset')
                : t('assets.dedup.assetMany', '{count} assets', {
                    count: row.original.merge_asset_ids.length,
                  })}{' '}
              ·{' '}
              {row.original.merge_finding_count === 1
                ? t('assets.dedup.findingOne', '1 finding')
                : t('assets.dedup.findingMany', '{count} findings', {
                    count: row.original.merge_finding_count,
                  })}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'created_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.flagged', 'Flagged')} />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        id: 'actions',
        header: () => <div className="text-end">{t('components.col.actions', 'Actions')}</div>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => (
          <Can permission={Permission.AssetsDelete}>
            <div className="flex justify-end gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={busyId === row.original.id}
                onClick={() => act(row.original.id, 'reject')}
              >
                <X className="me-1 h-3.5 w-3.5" />
                {t('assets.dedup.keepSeparate', 'Keep separate')}
              </Button>
              <Button
                size="sm"
                disabled={busyId === row.original.id}
                onClick={() => setPendingMerge(row.original)}
              >
                <GitMerge className="me-1 h-3.5 w-3.5" />
                {t('assets.dedup.merge', 'Merge')}
              </Button>
            </div>
          </Can>
        ),
      },
    ],
    [busyId, act, t]
  )

  return (
    <Main>
      <PageHeader
        title={t('assets.attention.title', 'Needs attention')}
        description={t(
          'assets.duplicates.description',
          'Approve or reject merges of assets that look like duplicates.'
        )}
      />
      <AssetsSectionTabs />
      <AssetAttentionTabs />
      <div className="mt-5" />

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full" />
          ))}
        </div>
      ) : error ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            {t('assets.dedup.loadFailed', 'Failed to load duplicate reviews.')}
          </CardContent>
        </Card>
      ) : reviews.length === 0 ? (
        <EmptyState
          icon={CopyCheck}
          title={t('assets.dedup.empty', 'No duplicates to review')}
          description={t(
            'assets.dedup.emptyHint',
            "The correlator hasn't flagged any assets as likely duplicates."
          )}
        />
      ) : (
        <DataTable
          columns={columns}
          data={reviews}
          searchPlaceholder={t('assets.dedup.search', 'Search reviews...')}
        />
      )}

      <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Check className="h-3 w-3" />
        {t(
          'assets.dedup.footnote',
          'Merging preserves findings from all assets on the kept asset; rejecting leaves them separate.'
        )}
      </p>
      <ConfirmDialog
        open={pendingMerge !== null}
        onOpenChange={(o) => !o && setPendingMerge(null)}
        destructive
        title={
          pendingMerge?.merge_asset_ids.length === 1
            ? t('confirm.dedup.mergeTitleOne', 'Merge 1 asset into {keep}?', {
                keep: pendingMerge?.keep_asset_name ?? '',
              })
            : t('confirm.dedup.mergeTitle', 'Merge {count} assets into {keep}?', {
                count: pendingMerge?.merge_asset_ids.length ?? 0,
                keep: pendingMerge?.keep_asset_name ?? '',
              })
        }
        desc={t(
          'confirm.dedup.mergeDesc',
          '{names} are removed from the inventory and their findings move to {keep}. This cannot be undone.',
          {
            names: pendingMerge?.merge_asset_names.join(', ') ?? '',
            keep: pendingMerge?.keep_asset_name ?? '',
          }
        )}
        confirmText={t('confirm.dedup.merge', 'Merge')}
        isLoading={busyId !== null}
        handleConfirm={() => (pendingMerge ? act(pendingMerge.id, 'approve') : undefined)}
      />
    </Main>
  )
}
