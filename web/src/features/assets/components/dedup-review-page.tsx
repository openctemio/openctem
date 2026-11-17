'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  PageHeader,
  RelativeTime,
  PageStack,
} from '@/features/shared'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Permission } from '@/lib/permissions'
import { accessStateOf } from '@/lib/api/access-state'
import { Check, CopyCheck } from 'lucide-react'
import { toast } from 'sonner'
import {
  useDedupReviews,
  approveDedupReview,
  rejectDedupReview,
  type DedupReview,
} from '../api/use-asset-dedup'
import { dedupReasonLabel, describeEvidence } from '../lib/asset-identity'
import { AssetsSectionTabs } from './assets-section-tabs'
import { AttentionQueueHeader } from './attention/attention-queue-header'

/** "2 assets, 5 findings": what a merge moves, in words. */
function useCountWords() {
  const { t } = useTranslation()
  return useMemo(
    () => ({
      findings: (n: number) =>
        n === 1
          ? t('assets.dedup.findingOne', '1 finding')
          : t('assets.dedup.findingMany', '{count} findings', { count: n }),
      assets: (n: number) =>
        n === 1
          ? t('assets.dedup.assetOne', '1 asset')
          : t('assets.dedup.assetMany', '{count} assets', { count: n }),
    }),
    [t]
  )
}

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
  const words = useCountWords()

  const reviews = useMemo(() => data?.data ?? [], [data])

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

  // One line per row: the identity with its type, the reason, what the flag
  // rests on, the asset that stays and the assets that merge into it. The two
  // decisions are in the row's menu.
  const columns = useMemo<ColumnDef<DedupReview>[]>(
    () => [
      {
        accessorKey: 'normalized_name',
        meta: { kind: 'name', pin: 'start', label: t('assets.dedup.identity', 'Identity') },
        enableHiding: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.identity', 'Identity')} />
        ),
        cell: ({ row }) => (
          <span className="flex min-w-0 items-baseline gap-2">
            <span className="truncate font-medium" title={row.original.normalized_name}>
              {row.original.normalized_name}
            </span>
            <span className="shrink-0 text-xs text-muted-foreground">
              {row.original.asset_type}
            </span>
          </span>
        ),
      },
      {
        id: 'reason',
        accessorFn: (r) => dedupReasonLabel(r.reason),
        meta: { kind: 'text', width: 168, label: t('assets.dedup.reason', 'Reason') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.reason', 'Reason')} />
        ),
        cell: ({ row }) => (
          <span className="block truncate text-sm">{dedupReasonLabel(row.original.reason)}</span>
        ),
      },
      {
        id: 'evidence',
        accessorFn: (r) => describeEvidence(r.evidence) ?? '',
        meta: {
          kind: 'text',
          minWidth: 160,
          maxWidth: 280,
          hideBelow: 1000,
          label: t('assets.dedup.evidence', 'Evidence'),
        },
        enableSorting: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.evidence', 'Evidence')} />
        ),
        cell: ({ row }) => {
          const evidence = describeEvidence(row.original.evidence)
          return evidence ? (
            <span className="block truncate text-sm text-muted-foreground" title={evidence}>
              {evidence}
            </span>
          ) : null
        },
      },
      {
        accessorKey: 'keep_asset_name',
        meta: { kind: 'asset', label: t('assets.dedup.keep', 'Keep') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.keep', 'Keep')} />
        ),
        cell: ({ row }) => (
          <span className="flex min-w-0 items-baseline gap-2">
            <span className="truncate" title={row.original.keep_asset_name}>
              {row.original.keep_asset_name}
            </span>
            <span className="shrink-0 text-xs text-muted-foreground">
              {words.findings(row.original.keep_finding_count)}
            </span>
          </span>
        ),
      },
      {
        id: 'merge',
        meta: {
          kind: 'text',
          minWidth: 220,
          maxWidth: 360,
          label: t('assets.dedup.mergeInto', 'Merge into it'),
        },
        header: t('assets.dedup.mergeInto', 'Merge into it'),
        enableSorting: false,
        cell: ({ row }) => {
          const names = row.original.merge_asset_names.join(', ')
          return (
            <span className="flex min-w-0 items-baseline gap-2">
              <span className="truncate" title={names}>
                {names}
              </span>
              <span className="shrink-0 text-xs text-muted-foreground">
                {t('assets.dedup.mergeCounts', '{assets}, {findings}', {
                  assets: words.assets(row.original.merge_asset_ids.length),
                  findings: words.findings(row.original.merge_finding_count),
                })}
              </span>
            </span>
          )
        },
      },
      {
        accessorKey: 'created_at',
        meta: { kind: 'datetime-recent', label: t('assets.dedup.flagged', 'Flagged') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.flagged', 'Flagged')} />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        id: 'actions',
        meta: { kind: 'actions', label: t('components.col.actions', 'Actions') },
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const busy =
            busyId === row.original.id
              ? t('assets.dedup.busy', 'This review is being decided')
              : undefined
          return (
            <DataTableRowActions
              title={row.original.normalized_name}
              label={t('common.rowActions.actionsFor', 'Actions for {name}', {
                name: row.original.normalized_name,
              })}
              actions={[
                {
                  label: t('assets.dedup.merge', 'Merge'),
                  onClick: () => setPendingMerge(row.original),
                  permission: Permission.AssetsDelete,
                  disabled: !!busy,
                  disabledReason: busy,
                },
                {
                  label: t('assets.dedup.keepSeparate', 'Keep separate'),
                  onClick: () => void act(row.original.id, 'reject'),
                  permission: Permission.AssetsDelete,
                  disabled: !!busy,
                  disabledReason: busy,
                },
              ]}
            />
          )
        },
      },
    ],
    [busyId, act, t, words]
  )

  const noAccess = !!error && accessStateOf(error) === 'no_access'

  return (
    <Main>
      <PageStack>
        <PageHeader title={t('assets.overview.title', 'Assets')} />
        <AssetsSectionTabs />
        <AttentionQueueHeader
          reason="duplicates"
          count={isLoading ? undefined : (data?.total ?? reviews.length)}
        />

        {noAccess ? (
          <NoAccessState title={t('assets.dedup.subject', 'the duplicate reviews')} />
        ) : (
          // Loading, a failed read and the empty queue are states of the table.
          <DataTable
            columns={columns}
            data={reviews}
            caption={t('assets.attention.tab.duplicates', 'Possible duplicates')}
            isLoading={isLoading && reviews.length === 0}
            error={error && reviews.length === 0 ? error : undefined}
            onRetry={() => void mutate()}
            errorTitle={t('assets.dedup.errorTitle', 'duplicate reviews')}
            getRowId={(r) => r.id}
            searchPlaceholder={t('assets.dedup.search', 'Search reviews…')}
            paginationNoun={t('assets.dedup.noun', 'reviews')}
            emptyState={{
              nothingYet: (
                <EmptyState
                  icon={CopyCheck}
                  title={t('assets.dedup.empty', 'No duplicates to review')}
                  description={t(
                    'assets.dedup.emptyHint',
                    "The correlator hasn't flagged any assets as likely duplicates."
                  )}
                />
              ),
            }}
          />
        )}

        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
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
            '{names} are removed from the inventory and their findings move to {keep}. The merge cannot be reversed from the console.',
            {
              names: pendingMerge?.merge_asset_names.join(', ') ?? '',
              keep: pendingMerge?.keep_asset_name ?? '',
            }
          )}
          confirmText={
            pendingMerge?.merge_asset_ids.length === 1
              ? t('confirm.dedup.mergeButtonOne', 'Merge 1 asset')
              : t('confirm.dedup.mergeButton', 'Merge {count} assets', {
                  count: pendingMerge?.merge_asset_ids.length ?? 0,
                })
          }
          typeToConfirm={pendingMerge ? String(pendingMerge.merge_asset_ids.length) : undefined}
          isLoading={busyId !== null}
          handleConfirm={() => (pendingMerge ? act(pendingMerge.id, 'approve') : undefined)}
        />
      </PageStack>
    </Main>
  )
}
