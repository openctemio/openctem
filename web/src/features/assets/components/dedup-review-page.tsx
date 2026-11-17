'use client'

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  PageHeader,
  RelativeTime,
  PageStack,
} from '@/features/shared'
import { QueueCard, QueueDecisionActions, QueueEmpty, useQueueAnnouncer } from '@/features/queue'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'
import { accessStateOf } from '@/lib/api/access-state'
import { Check } from 'lucide-react'
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

/** Merge + Keep separate in en (the wider) and the cell padding: measured 208. */
const DECISIONS_WIDTH = 216

/** Column floors and the frame widths below which a column is dropped. */
const WIDTH = {
  identityMin: 200,
  reason: 168,
  keepMin: 180,
  mergeMin: 180,
  // "less than a minute ago" / "khoảng 20 giờ trước" whole.
  flagged: 160,
  // 1440 screen (frame 1116): every column but Evidence; 1280 (956): no Flagged.
  evidenceFrom: 1300,
  flaggedFrom: 1100,
  reasonFrom: 1000,
} as const

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
  const reasonText = useCallback(
    (reason: string | null | undefined) =>
      t(`assets.dedup.reasonLabel.${reason || 'none'}`, dedupReasonLabel(reason)),
    [t]
  )
  // Both decisions need assets:delete (a merge deletes the duplicates); the
  // API checks it again.
  const canDecide = useHasPermission(Permission.AssetsDelete)
  // Every outcome is also said to assistive technology (one status region).
  const { announce, region } = useQueueAnnouncer()

  const reviews = useMemo(() => data?.data ?? [], [data])

  // useCallback so the columns memo can depend on it; mutate is stable (SWR).
  const act = useCallback(
    async (id: string, action: 'approve' | 'reject') => {
      setBusyId(id)
      try {
        if (action === 'approve') {
          await approveDedupReview(id)
          setPendingMerge(null)
          const done = t('assets.dedup.merged', 'Duplicates merged')
          toast.success(done)
          announce(done)
        } else {
          await rejectDedupReview(id)
          const done = t('assets.dedup.kept', 'Kept as separate assets')
          toast.success(done)
          announce(done)
        }
        await mutate()
      } catch {
        const failed =
          action === 'approve'
            ? t('assets.dedup.approveFailed', 'Failed to approve review')
            : t('assets.dedup.rejectFailed', 'Failed to reject review')
        toast.error(failed)
        announce(failed)
      } finally {
        setBusyId(null)
      }
    },
    [announce, mutate, t]
  )

  /** The two decisions of a review: Merge (asks first) and Keep separate. */
  const decisions = useCallback(
    (review: DedupReview, layout: 'row' | 'card' = 'row') => (
      <QueueDecisionActions
        name={review.normalized_name}
        layout={layout}
        canDecide={canDecide}
        busy={busyId === review.id}
        onApprove={() => setPendingMerge(review)}
        onReject={() => void act(review.id, 'reject')}
        approveLabel={t('assets.dedup.merge', 'Merge')}
        rejectLabel={t('assets.dedup.keepSeparate', 'Keep separate')}
      />
    ),
    [act, busyId, canDecide, t]
  )

  // One line per row: the identity with its type, the reason, what the flag
  // rests on, the asset that stays and the assets that merge into it. The two
  // decisions end the row. Columns drop by the frame's width, evidence first.
  const columns = useMemo<ColumnDef<DedupReview>[]>(
    () => [
      {
        accessorKey: 'normalized_name',
        meta: {
          kind: 'name',
          pin: 'start',
          minWidth: WIDTH.identityMin,
          label: t('assets.dedup.identity', 'Identity'),
        },
        enableHiding: false,
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.identity', 'Identity')} />
        ),
        // No width of its own (w-0): a long identity never widens the table.
        cell: ({ row }) => (
          <span className="flex w-0 min-w-full items-baseline gap-2">
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
        accessorFn: (r) => reasonText(r.reason),
        meta: {
          kind: 'text',
          width: WIDTH.reason,
          hideBelow: WIDTH.reasonFrom,
          label: t('assets.dedup.reason', 'Reason'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.reason', 'Reason')} />
        ),
        cell: ({ row }) => (
          <span className="block truncate text-sm">{reasonText(row.original.reason)}</span>
        ),
      },
      {
        id: 'evidence',
        accessorFn: (r) => describeEvidence(r.evidence) ?? '',
        meta: {
          kind: 'text',
          minWidth: 160,
          maxWidth: 280,
          hideBelow: WIDTH.evidenceFrom,
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
        meta: { kind: 'asset', minWidth: WIDTH.keepMin, label: t('assets.dedup.keep', 'Keep') },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.keep', 'Keep')} />
        ),
        cell: ({ row }) => (
          <span className="flex w-0 min-w-full items-baseline gap-2">
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
          minWidth: WIDTH.mergeMin,
          maxWidth: 360,
          label: t('assets.dedup.mergeInto', 'Merge into it'),
        },
        header: t('assets.dedup.mergeInto', 'Merge into it'),
        enableSorting: false,
        cell: ({ row }) => {
          const names = row.original.merge_asset_names.join(', ')
          return (
            <span className="flex w-0 min-w-full items-baseline gap-2">
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
        meta: {
          kind: 'datetime-recent',
          width: WIDTH.flagged,
          hideBelow: WIDTH.flaggedFrom,
          label: t('assets.dedup.flagged', 'Flagged'),
        },
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('assets.dedup.flagged', 'Flagged')} />
        ),
        cell: ({ row }) => <RelativeTime date={row.original.created_at} />,
      },
      {
        // The two decisions, in the row (no menu to open first).
        id: 'actions',
        meta: {
          kind: 'actions',
          width: DECISIONS_WIDTH,
          label: t('components.col.actions', 'Actions'),
        },
        header: () => <span className="sr-only">{t('components.col.actions', 'Actions')}</span>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => decisions(row.original),
      },
    ],
    [decisions, reasonText, t, words]
  )

  const noAccess = !!error && accessStateOf(error) === 'no_access'

  return (
    <Main>
      <PageStack>
        <PageHeader title={t('assets.overview.title', 'Assets')} />
        <AssetsSectionTabs />
        <AttentionQueueHeader
          reason="duplicates"
          // No count while loading or after a failed read: 0 would be a claim.
          count={isLoading || error ? undefined : (data?.total ?? reviews.length)}
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
            pinActions
            emptyState={{
              // The API returns the reviews that wait; none waiting is the
              // queue's done state.
              nothingYet: (
                <QueueEmpty
                  kind="nothing-waiting"
                  title={t('assets.dedup.empty', 'No duplicates to review')}
                  hint={t(
                    'assets.dedup.emptyHint',
                    "The correlator hasn't flagged any assets as likely duplicates."
                  )}
                />
              ),
            }}
            mobileRow={(review) => (
              <QueueCard
                data-testid="dedup-phone-card"
                title={
                  <span className="flex min-w-0 items-baseline gap-2">
                    <span className="truncate font-medium" title={review.normalized_name}>
                      {review.normalized_name}
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {review.asset_type}
                    </span>
                  </span>
                }
                marks={<span className="text-xs font-medium">{reasonText(review.reason)}</span>}
                meta={
                  <>
                    <span className="min-w-0 truncate">
                      {t('assets.dedup.card.keep', 'Keep {name} ({findings})', {
                        name: review.keep_asset_name,
                        findings: words.findings(review.keep_finding_count),
                      })}
                    </span>
                    <span className="min-w-0 truncate">
                      {t(
                        'assets.dedup.card.merge',
                        'Merge {names} into it ({assets}, {findings})',
                        {
                          names: review.merge_asset_names.join(', '),
                          assets: words.assets(review.merge_asset_ids.length),
                          findings: words.findings(review.merge_finding_count),
                        }
                      )}
                    </span>
                    <RelativeTime date={review.created_at} />
                  </>
                }
                reason={
                  describeEvidence(review.evidence) ? (
                    <span className="line-clamp-2 text-xs text-muted-foreground">
                      {describeEvidence(review.evidence)}
                    </span>
                  ) : undefined
                }
                actions={decisions(review, 'card')}
              />
            )}
          />
        )}

        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Check className="h-3 w-3" />
          {t(
            'assets.dedup.footnote',
            'Merging preserves findings from all assets on the kept asset; rejecting leaves them separate.'
          )}
        </p>
        {region}
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
