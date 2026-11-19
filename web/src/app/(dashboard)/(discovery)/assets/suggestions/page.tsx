'use client'

/**
 * Assets › Needs attention › Relationships: the relationship suggestions queue.
 * Each row proposes one relationship between two assets; a reviewer approves
 * it (the relationship is created) or dismisses it, in the row. The type can
 * be changed from the row's More before approving. Every write is the API's
 * own call behind assets:write, as before.
 */

import { useCallback, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { ArrowRight, CheckCheck, Loader2, MoreHorizontal, Sparkles } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { DataTable, PageHeader, PageStack, usePhoneSelectMode } from '@/features/shared'
import type {
  DataTableBulk,
  DataTableSelection,
} from '@/features/shared/components/data-table/data-table-selection'
import { NoAccessState } from '@/features/shared/components/no-access-state'
import { Button } from '@/components/ui/button'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { ConfirmDialog, ConfirmSample } from '@/components/confirm-dialog'
import { AssetsSectionTabs } from '@/features/assets/components/assets-section-tabs'
import { AttentionQueueHeader } from '@/features/assets/components/attention/attention-queue-header'
import { getAssetTypeLabel } from '@/features/assets/lib/asset-type-icon'
import { relationVerbFallback, relationVerbKey } from '@/features/assets/lib/relationship-verbs'
import {
  QueueCard,
  QueueDecisionActions,
  QueueEmpty,
  useQueueAnnouncer,
} from '@/features/shared/components/queue'
import {
  useRelationshipSuggestions,
  useApproveSuggestion,
  useDismissSuggestion,
  useApproveAllSuggestions,
  useGenerateSuggestions,
  useUpdateSuggestionType,
  useApproveBatchSuggestions,
  type RelationshipSuggestion,
} from '@/features/relationships/api/use-relationship-suggestions'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import { useListParams } from '@/hooks/use-list-params'
import { accessStateOf } from '@/lib/api/access-state'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'

/** The types a suggestion can be changed to (the same list as before). */
const SUGGESTION_TYPES = [
  'contains',
  'resolves_to',
  'cname_of',
  'runs_on',
  'deployed_to',
  'depends_on',
  'exposes',
  'sends_data_to',
  'stores_data_in',
  'authenticates_to',
  'granted_to',
  'has_access_to',
  'load_balances',
  'protected_by',
  'monitors',
  'manages',
  'peer_of',
  'replicates_to',
] as const

const WIDTH = {
  sourceMin: 200,
  // "Alias (CNAME) of" / "Phân giải tới" whole, with the arrow.
  relationship: 184,
  reasonMin: 160,
  reasonMax: 320,
  // "Confidence" / "Độ tin cậy" whole.
  confidence: 104,
  // Approve + Dismiss + More in en and vi, and the cell padding.
  decisions: 236,
} as const

type T = ReturnType<typeof useTranslation>['t']

/** The verb of a relationship, read from its source ("Resolves to"). */
function verbOf(t: T, type: string): string {
  return t(relationVerbKey(type, 'outgoing'), relationVerbFallback(type, 'outgoing'))
}

/** An asset in a row: its name (cut inside the cell), then its type. */
function AssetCell({ t, type, name, id }: { t: T; type: string; name: string; id: string }) {
  const shown = name || id.slice(0, 8)
  return (
    // No width of its own (w-0): a long name never widens the table.
    <span className="flex w-0 min-w-full items-baseline gap-2">
      <span className="truncate font-medium" title={shown} dir="auto">
        {shown}
      </span>
      <span className="shrink-0 text-xs text-muted-foreground">
        {t(`assets.typeLabel.${type}`, getAssetTypeLabel(type))}
      </span>
    </span>
  )
}

export default function RelationshipSuggestionsPage() {
  const { t } = useTranslation()
  const isPhone = useIsMobile()
  // Search, page and size live in the address, so a queue position can be
  // linked to; the search reaches the request once it settles.
  const list = useListParams()
  const { page, perPage, searchTerm } = list

  // Reviewing (scan, approve, dismiss, change the type) needs assets:write,
  // the permission the API checks; readers see the queue only.
  const { can } = usePermissions()
  const canReview = can(Permission.AssetsWrite)

  const { data, error, isLoading, isValidating, mutate } = useRelationshipSuggestions(
    'pending',
    page,
    perPage,
    searchTerm || undefined
  )
  const { trigger: approve, isMutating: isApproving } = useApproveSuggestion()
  const { trigger: dismiss, isMutating: isDismissing } = useDismissSuggestion()
  const { trigger: approveAll, isMutating: isApprovingAll } = useApproveAllSuggestions()
  const { trigger: generate, isMutating: isGenerating } = useGenerateSuggestions()
  const { trigger: updateType } = useUpdateSuggestionType()
  const { trigger: approveBatch, isMutating: isBatchApproving } = useApproveBatchSuggestions()

  const suggestions = useMemo(() => data?.data ?? [], [data])
  const total = data?.total ?? 0
  const isMutating = isApproving || isDismissing || isApprovingAll || isBatchApproving
  const firstLoad = isLoading && !data
  const noAccess = !!error && accessStateOf(error) === 'no_access'

  // Every outcome is also said to assistive technology (one status region).
  const { announce, region } = useQueueAnnouncer()
  const say = useCallback(
    (ok: boolean, text: string) => {
      if (ok) toast.success(text)
      else toast.error(text)
      announce(text)
    },
    [announce]
  )

  const [selected, setSelected] = useState<RelationshipSuggestion[]>([])
  const [selectionEpoch, setSelectionEpoch] = useState(0)
  const [confirmAll, setConfirmAll] = useState(false)
  const [confirmSelected, setConfirmSelected] = useState(false)
  const clearSelection = useCallback(() => {
    setSelected([])
    setSelectionEpoch((n) => n + 1)
  }, [])
  const onSelectionChange = useCallback(
    (selection: DataTableSelection<RelationshipSuggestion> | null) =>
      setSelected(selection?.kind === 'ids' ? selection.rows : []),
    []
  )

  const rowName = useCallback(
    (s: RelationshipSuggestion) =>
      t('assets.suggestions.rowName', '{source} to {target}', {
        source: s.source_asset_name || s.source_asset_id.slice(0, 8),
        target: s.target_asset_name || s.target_asset_id.slice(0, 8),
      }),
    [t]
  )

  const handleApprove = useCallback(
    async (id: string) => {
      try {
        await approve(id)
        say(true, t('assets.suggestions.toast.approved', 'Relationship created'))
        clearSelection()
      } catch (err) {
        say(
          false,
          getErrorMessage(err, t('assets.suggestions.toast.approveFailed', 'Failed to approve'))
        )
      }
    },
    [approve, clearSelection, say, t]
  )

  const handleDismiss = useCallback(
    async (id: string) => {
      try {
        await dismiss(id)
        say(true, t('assets.suggestions.toast.dismissed', 'Suggestion dismissed'))
        clearSelection()
      } catch (err) {
        say(
          false,
          getErrorMessage(err, t('assets.suggestions.toast.dismissFailed', 'Failed to dismiss'))
        )
      }
    },
    [dismiss, clearSelection, say, t]
  )

  const handleUpdateType = useCallback(
    async (id: string, type: string) => {
      try {
        await updateType({ id, relationship_type: type })
        say(
          true,
          t('assets.suggestions.toast.typeChanged', 'Changed to {type}', { type: verbOf(t, type) })
        )
      } catch (err) {
        say(
          false,
          getErrorMessage(err, t('assets.suggestions.toast.typeFailed', 'Failed to update type'))
        )
      }
    },
    [updateType, say, t]
  )

  const handleApproveSelected = async () => {
    const ids = selected.map((s) => s.id)
    try {
      const result = await approveBatch(ids)
      say(
        true,
        t('assets.suggestions.toast.approvedMany', '{count} relationships created', {
          count: result?.count ?? ids.length,
        })
      )
      clearSelection()
    } catch (err) {
      say(
        false,
        getErrorMessage(
          err,
          t('assets.suggestions.toast.approveSelectedFailed', 'Failed to approve selected')
        )
      )
    }
  }

  const handleApproveAll = async () => {
    try {
      await approveAll()
      say(true, t('assets.suggestions.toast.approvedAll', 'All relationships created'))
      clearSelection()
    } catch (err) {
      say(
        false,
        getErrorMessage(
          err,
          t('assets.suggestions.toast.approveAllFailed', 'Failed to approve all')
        )
      )
    }
  }

  const handleGenerate = async () => {
    try {
      await generate()
      say(true, t('assets.suggestions.toast.generated', 'Suggestions generated'))
    } catch (err) {
      say(
        false,
        getErrorMessage(err, t('assets.suggestions.toast.generateFailed', 'Failed to generate'))
      )
    }
  }

  /** Approve and Dismiss in the row; the type change is in its More. */
  const decisions = useCallback(
    (s: RelationshipSuggestion, layout: 'row' | 'card' = 'row') => {
      const current = t('assets.suggestions.currentType', 'The current type')
      const menu: ActionMenuEntry[] = [
        {
          kind: 'sub',
          id: 'change-type',
          label: t('assets.suggestions.changeType', 'Change relationship type'),
          items: SUGGESTION_TYPES.map((type) => ({
            id: `type-${type}`,
            label: verbOf(t, type),
            disabledReason: type === s.relationship_type ? current : undefined,
            onSelect: () => void handleUpdateType(s.id, type),
          })),
        },
      ]
      return (
        <QueueDecisionActions
          name={rowName(s)}
          layout={layout}
          canDecide={canReview}
          busy={isMutating}
          onApprove={() => void handleApprove(s.id)}
          onReject={() => void handleDismiss(s.id)}
          approveLabel={t('assets.suggestions.approve', 'Approve')}
          rejectLabel={t('assets.suggestions.dismiss', 'Dismiss')}
          menu={canReview ? menu : undefined}
        />
      )
    },
    [canReview, handleApprove, handleDismiss, handleUpdateType, isMutating, rowName, t]
  )

  const columns = useMemo<ColumnDef<RelationshipSuggestion>[]>(() => {
    const label = {
      source: t('assets.suggestions.col.source', 'Source'),
      relationship: t('assets.suggestions.col.relationship', 'Relationship'),
      target: t('assets.suggestions.col.target', 'Target'),
      reason: t('assets.suggestions.col.reason', 'Reason'),
      confidence: t('assets.suggestions.col.confidence', 'Confidence'),
      actions: t('components.col.actions', 'Actions'),
    }
    const all: ColumnDef<RelationshipSuggestion>[] = [
      {
        id: 'source',
        meta: { kind: 'name', pin: 'start', minWidth: WIDTH.sourceMin, label: label.source },
        header: label.source,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => (
          <AssetCell
            t={t}
            type={row.original.source_asset_type}
            name={row.original.source_asset_name}
            id={row.original.source_asset_id}
          />
        ),
      },
      {
        id: 'relationship',
        meta: { kind: 'text', width: WIDTH.relationship, label: label.relationship },
        header: label.relationship,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex min-w-0 items-center gap-1.5 text-sm">
            <ArrowRight
              className="size-3.5 shrink-0 text-muted-foreground rtl:rotate-180"
              aria-hidden
            />
            <span className="truncate">{verbOf(t, row.original.relationship_type)}</span>
          </span>
        ),
      },
      {
        id: 'target',
        meta: { kind: 'asset', label: label.target },
        header: label.target,
        enableSorting: false,
        cell: ({ row }) => (
          <AssetCell
            t={t}
            type={row.original.target_asset_type}
            name={row.original.target_asset_name}
            id={row.original.target_asset_id}
          />
        ),
      },
      {
        accessorKey: 'reason',
        meta: {
          kind: 'text',
          minWidth: WIDTH.reasonMin,
          maxWidth: WIDTH.reasonMax,
          // Dropped first: a 1440 screen (frame 1116) holds the rest whole.
          hideBelow: 1200,
          label: label.reason,
        },
        header: label.reason,
        enableSorting: false,
        cell: ({ row }) => (
          <span
            className="block w-0 min-w-full truncate text-sm text-muted-foreground"
            title={row.original.reason}
          >
            {row.original.reason}
          </span>
        ),
      },
      {
        accessorKey: 'confidence',
        meta: {
          kind: 'number',
          width: WIDTH.confidence,
          // Then this one: a 1280 screen (frame 956).
          hideBelow: 1000,
          label: label.confidence,
        },
        header: label.confidence,
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-sm tabular-nums">{Math.round(row.original.confidence * 100)}%</span>
        ),
      },
      {
        id: 'actions',
        meta: { kind: 'actions', width: WIDTH.decisions, label: label.actions },
        header: () => <span className="sr-only">{label.actions}</span>,
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => decisions(row.original),
      },
    ]
    // Readers see the queue without the decision column.
    return canReview ? all : all.filter((c) => c.id !== 'actions')
  }, [canReview, decisions, t])

  // No checkbox column unless the user may approve several at once.
  const bulk: DataTableBulk<RelationshipSuggestion> | undefined = canReview
    ? {
        rowLabel: rowName,
        noun: (count) => t('assets.suggestions.bulk.noun', 'suggestions selected', { count }),
        onSelectionChange,
        actions: (
          <Button
            variant="ghost"
            size="sm"
            disabled={isBatchApproving}
            onClick={() => setConfirmSelected(true)}
          >
            {t('assets.suggestions.approve', 'Approve')}
          </Button>
        ),
      }
    : undefined
  // Phone cards have no header checkbox: "Select" is in the queue's More.
  const phoneSelect = usePhoneSelectMode(isPhone && !!bulk)

  // On a phone the header is one More (its buttons would take a row of
  // their own above the queue): Select, Scan and Approve all.
  const phoneItems: ActionMenuEntry[] =
    canReview && isPhone
      ? [
          {
            id: 'scan',
            label: t('assets.suggestions.scan', 'Scan'),
            disabledReason: isGenerating
              ? t('assets.suggestions.scanning', 'Scanning for suggestions')
              : undefined,
            onSelect: () => void handleGenerate(),
          },
          ...(total > 0
            ? [
                {
                  id: 'approve-all',
                  label: t('assets.suggestions.approveAllShort', 'Approve all'),
                  onSelect: () => setConfirmAll(true),
                },
              ]
            : []),
        ]
      : []
  const moreItems = [...(phoneSelect.item ? [phoneSelect.item] : []), ...phoneItems]

  return (
    <Main>
      <PageStack>
        <PageHeader title={t('assets.overview.title', 'Assets')}>
          {canReview && !isPhone && (
            <Button variant="outline" size="sm" onClick={handleGenerate} disabled={isGenerating}>
              {isGenerating ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <Sparkles className="me-2 h-4 w-4" aria-hidden />
              )}
              {t('assets.suggestions.scan', 'Scan')}
            </Button>
          )}
          {moreItems.length > 0 && (
            <ActionMenu
              title={t('assets.attention.tab.relationships', 'Relationships')}
              label={t('common.actionMenu.label', 'Actions for {name}', {
                name: t('assets.attention.tab.relationships', 'Relationships'),
              })}
              items={moreItems}
              trigger={
                <Button
                  variant="outline"
                  size="icon"
                  aria-label={t('assets.inventoryPage.moreActions', 'More actions')}
                >
                  <MoreHorizontal className="h-4 w-4" aria-hidden />
                </Button>
              }
            />
          )}
          {canReview && !isPhone && total > 0 && (
            <Button size="sm" disabled={isApprovingAll} onClick={() => setConfirmAll(true)}>
              <CheckCheck className="me-2 h-4 w-4" aria-hidden />
              {t('assets.suggestions.approveAllShort', 'Approve all')}
            </Button>
          )}
        </PageHeader>
        <AssetsSectionTabs />
        <AttentionQueueHeader
          reason="relationships"
          count={firstLoad || error ? undefined : total}
        />

        {noAccess ? (
          <NoAccessState title={t('assets.suggestions.subject', 'the relationship suggestions')} />
        ) : (
          <DataTable
            columns={columns}
            data={suggestions}
            caption={t('assets.attention.tab.relationships', 'Relationships')}
            // The first read: skeleton rows under a toolbar that stays.
            isLoading={firstLoad}
            isRefreshing={isValidating && !!data}
            refreshingLabel={t('assets.suggestions.refreshing', 'Refreshing suggestions')}
            // A failed read keeps the search, so it can still be changed.
            error={error && !data ? error : undefined}
            onRetry={() => void mutate()}
            errorTitle={t('assets.suggestions.errorTitle', 'suggestions')}
            showSearch={false}
            search={{
              value: list.q,
              onChange: list.setSearch,
              placeholder: t('assets.suggestions.search.placeholder', 'Search by asset name…'),
              label: t('assets.suggestions.search.label', 'Search suggestions'),
            }}
            getRowId={(s) => s.id}
            manualPagination
            rowCount={total}
            pagination={list.pagination}
            onPaginationChange={list.setPagination}
            paginationNoun={t('assets.suggestions.noun', 'suggestions')}
            pinActions
            bulk={bulk}
            selectMode={phoneSelect.selectMode}
            resetSelectionKey={selectionEpoch}
            showSelectionCount={false}
            isFiltered={!!list.q}
            onClearFilters={() => list.setSearch('')}
            emptyState={{
              nothingYet: (
                <QueueEmpty
                  kind="nothing-waiting"
                  title={t('assets.suggestions.empty.title', 'No pending suggestions')}
                  hint={
                    canReview
                      ? t(
                          'assets.suggestions.empty.hintReviewer',
                          'Run a scan to detect new connections between assets.'
                        )
                      : t(
                          'assets.suggestions.empty.hintReader',
                          'No relationships are waiting for review.'
                        )
                  }
                />
              ),
              noMatch: {
                title: t('assets.suggestions.empty.noMatch', 'No matching suggestions'),
                hint: t('assets.suggestions.empty.noMatchHint', 'Try a different search term.'),
              },
            }}
            mobileRow={(s) => (
              <QueueCard
                data-testid="suggestion-phone-card"
                title={
                  <span className="flex min-w-0 flex-col gap-0.5">
                    <AssetCell
                      t={t}
                      type={s.source_asset_type}
                      name={s.source_asset_name}
                      id={s.source_asset_id}
                    />
                    <span className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
                      <ArrowRight className="size-3 shrink-0 rtl:rotate-180" aria-hidden />
                      {verbOf(t, s.relationship_type)}
                    </span>
                    <AssetCell
                      t={t}
                      type={s.target_asset_type}
                      name={s.target_asset_name}
                      id={s.target_asset_id}
                    />
                  </span>
                }
                meta={
                  <span className="tabular-nums">
                    {t('assets.suggestions.confidenceValue', 'Confidence {value}%', {
                      value: Math.round(s.confidence * 100),
                    })}
                  </span>
                }
                reason={
                  s.reason ? (
                    <span className="line-clamp-2 text-xs text-muted-foreground">{s.reason}</span>
                  ) : undefined
                }
                actions={decisions(s, 'card')}
              />
            )}
          />
        )}

        {region}
        <ConfirmDialog
          open={confirmAll}
          onOpenChange={setConfirmAll}
          title={t('confirm.suggestions.approveAllTitle', 'Approve all {count} suggestions?', {
            count: total,
          })}
          desc={t(
            'confirm.suggestions.approveAllDesc',
            'This creates {count} relationships between your assets, including suggestions on other pages and ones hidden by the search. You can remove a relationship afterwards from the asset it belongs to.',
            { count: total }
          )}
          confirmText={t('confirm.suggestions.approveAllButton', 'Approve {count} suggestions', {
            count: total,
          })}
          handleConfirm={async () => {
            await handleApproveAll()
            setConfirmAll(false)
          }}
        />

        <ConfirmDialog
          open={confirmSelected}
          onOpenChange={setConfirmSelected}
          title={t('confirm.suggestions.approveSelectedTitle', 'Approve {count} suggestions?', {
            count: selected.length,
          })}
          desc={t(
            'confirm.suggestions.approveSelectedDesc',
            'This creates {count} relationships between your assets. You can remove a relationship afterwards from the asset it belongs to.',
            { count: selected.length }
          )}
          confirmText={t(
            'confirm.suggestions.approveSelectedButton',
            'Approve {count} suggestions',
            {
              count: selected.length,
            }
          )}
          handleConfirm={async () => {
            await handleApproveSelected()
            setConfirmSelected(false)
          }}
        >
          <ConfirmSample names={selected.map(rowName)} total={selected.length} />
        </ConfirmDialog>
      </PageStack>
    </Main>
  )
}
