'use client'

import { useMemo, useState } from 'react'
import {
  ArchiveRestore,
  Archive,
  ArrowDown,
  ArrowUp,
  MoreHorizontal,
  Pencil,
  Plus,
} from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { GatedButton } from '@/features/shared'
import {
  CANONICAL_STATUSES,
  archiveSubStatus,
  reactivateSubStatus,
  updateSubStatus,
  type LifecycleSubStatus,
} from '../../api/use-finding-lifecycles'
import { closureReasonLabel } from '../../lib/closure'
import type { FindingStatus } from '../../types'
import { SubStatusDialog } from './sub-status-dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { SubStatusPill } from './sub-status-pill'

interface SubStatusLanesProps {
  subStatuses: LifecycleSubStatus[]
  colors: string[]
  canWrite: boolean
  /** The plan allows no more sub-statuses. */
  limitReached: boolean
  onChanged: () => void
}

/**
 * One lane per canonical status with its sub-statuses: add, rename, reorder,
 * archive and reactivate. Archiving is refused by the API while a published
 * lifecycle uses the sub-status; the error says so.
 */
export function SubStatusLanes({
  subStatuses,
  colors,
  canWrite,
  limitReached,
  onChanged,
}: SubStatusLanesProps) {
  const { t } = useTranslation()
  const [dialog, setDialog] = useState<{ status: FindingStatus; sub?: LifecycleSubStatus } | null>(
    null
  )
  const [busy, setBusy] = useState<string | null>(null)
  const [archiving, setArchiving] = useState<LifecycleSubStatus | null>(null)

  const byStatus = useMemo(() => {
    const m = new Map<FindingStatus, LifecycleSubStatus[]>()
    for (const s of CANONICAL_STATUSES) m.set(s, [])
    for (const s of subStatuses) m.get(s.canonical_status)?.push(s)
    for (const list of m.values()) list.sort((a, b) => a.sort_order - b.sort_order)
    return m
  }, [subStatuses])

  const run = async (id: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(id)
    try {
      await fn()
      toast.success(done)
      onChanged()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findingLifecycle.subStatus.actionFailed', 'The change failed'))
      )
    } finally {
      setBusy(null)
    }
  }

  const move = (list: LifecycleSubStatus[], index: number, delta: -1 | 1) => {
    const a = list[index]
    const b = list[index + delta]
    if (!a || !b) return
    // Renumber the lane 0..n-1 in the new order and save only what changed,
    // so equal or sparse sort_order values still end up distinct.
    const next = [...list]
    next[index] = b
    next[index + delta] = a
    const changes = next
      .map((s, order) => ({ s, order }))
      .filter(({ s, order }) => s.sort_order !== order)
    void run(
      a.id,
      async () => {
        for (const { s, order } of changes) await updateSubStatus(s.id, { sort_order: order })
      },
      t('findingLifecycle.subStatus.reordered', 'Order saved')
    )
  }

  const addReason = limitReached
    ? t('findingLifecycle.plan.subStatusesReachedShort', 'Limit of sub-statuses reached')
    : t('findingLifecycle.readOnly', 'Needs the Manage Finding Lifecycles permission')

  const subStatusItems = (
    status: FindingStatus,
    s: LifecycleSubStatus,
    i: number,
    list: LifecycleSubStatus[]
  ): ActionMenuEntry[] =>
    !s.archived
      ? [
          {
            id: 'edit',
            label: t('findingLifecycle.subStatus.editShort', 'Edit'),
            icon: Pencil,
            onSelect: () => setDialog({ status, sub: s }),
          },
          {
            id: 'up',
            label: t('findingLifecycle.subStatus.moveUpShort', 'Move up'),
            icon: ArrowUp,
            disabledReason:
              i === 0 ? t('findingLifecycle.subStatus.reasonFirst', 'Already first') : undefined,
            onSelect: () => move(list, i, -1),
          },
          {
            id: 'down',
            label: t('findingLifecycle.subStatus.moveDownShort', 'Move down'),
            icon: ArrowDown,
            disabledReason:
              i === list.length - 1
                ? t('findingLifecycle.subStatus.reasonLast', 'Already last')
                : undefined,
            onSelect: () => move(list, i, 1),
          },
          {
            id: 'archive',
            label: t('findingLifecycle.subStatus.archiveShort', 'Archive'),
            icon: Archive,
            onSelect: () => setArchiving(s),
          },
        ]
      : [
          {
            id: 'reactivate',
            label: t('findingLifecycle.subStatus.reactivateShort', 'Reactivate'),
            icon: ArchiveRestore,
            disabledReason: limitReached
              ? addReason
              : busy !== null
                ? t('findingLifecycle.subStatus.busy', 'Saving...')
                : undefined,
            onSelect: () =>
              void run(
                s.id,
                () => reactivateSubStatus(s.id),
                t('findingLifecycle.subStatus.reactivated', 'Sub-status reactivated')
              ),
          },
        ]

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {CANONICAL_STATUSES.map((status) => {
        const list = byStatus.get(status) ?? []
        const live = list.filter((s) => !s.archived)
        return (
          <section
            key={status}
            aria-label={t(`findings.status.${status}`, status)}
            className="flex min-w-0 flex-col rounded-lg border bg-card p-3"
          >
            <div className="mb-2 flex items-center justify-between gap-2">
              <h3 className="truncate text-sm font-semibold">
                {t(`findings.status.${status}`, status)}
              </h3>
              <span className="text-xs text-muted-foreground tabular-nums">{live.length}</span>
            </div>
            {list.length === 0 ? (
              <p className="mb-2 text-xs text-muted-foreground">
                {t('findingLifecycle.lane.empty', 'Only the status itself')}
              </p>
            ) : (
              <ul className="mb-2 space-y-1.5">
                {list.map((s, i) => (
                  <li
                    key={s.id}
                    className="flex min-w-0 items-start justify-between gap-1 rounded-md px-1 py-1 hover:bg-muted/50"
                  >
                    <div className="min-w-0 space-y-0.5">
                      <div className="flex min-w-0 flex-wrap items-center gap-1">
                        <SubStatusPill subStatus={s} />
                        {s.archived && (
                          <Badge variant="outline" className="text-xs">
                            {t('findingLifecycle.subStatus.archived', 'Archived')}
                          </Badge>
                        )}
                      </div>
                      <div className="truncate font-mono text-xs text-muted-foreground">
                        {s.key}
                        {s.closure_reason ? `, ${closureReasonLabel(t, s.closure_reason)}` : ''}
                      </div>
                    </div>
                    {canWrite && (
                      <ActionMenu
                        title={s.name}
                        label={t('findingLifecycle.subStatus.actions', 'Actions for {name}', {
                          name: s.name,
                        })}
                        items={subStatusItems(status, s, i, list)}
                        trigger={
                          <Button
                            size="icon"
                            variant="ghost"
                            className="shrink-0"
                            disabled={busy !== null}
                            aria-label={t(
                              'findingLifecycle.subStatus.actions',
                              'Actions for {name}',
                              {
                                name: s.name,
                              }
                            )}
                          >
                            <MoreHorizontal className="size-4" />
                          </Button>
                        }
                      />
                    )}
                  </li>
                ))}
              </ul>
            )}
            <div className="mt-auto">
              <GatedButton
                allowed={canWrite && !limitReached}
                reason={addReason}
                size="sm"
                variant="ghost"
                className="h-7 px-2 text-xs"
                onClick={() => setDialog({ status })}
                aria-label={t('findingLifecycle.lane.addTo', 'Add a sub-status to {status}', {
                  status: t(`findings.status.${status}`, status),
                })}
              >
                <Plus className="mr-1 size-3.5" />
                {t('findingLifecycle.lane.add', 'Add')}
              </GatedButton>
            </div>
          </section>
        )
      })}
      <ConfirmDialog
        open={archiving !== null}
        onOpenChange={(o) => !o && setArchiving(null)}
        title={t('findingLifecycle.subStatus.archiveTitle', 'Archive the sub-status "{name}"?', {
          name: archiving?.name ?? '',
        })}
        desc={t(
          'findingLifecycle.subStatus.archiveDesc',
          'It can no longer be picked for findings. You can reactivate it later from its lane.'
        )}
        confirmText={t('findingLifecycle.subStatus.archiveButton', 'Archive sub-status')}
        destructive
        handleConfirm={async () => {
          const target = archiving
          setArchiving(null)
          if (!target) return
          await run(
            target.id,
            () => archiveSubStatus(target.id),
            t('findingLifecycle.subStatus.archivedToast', 'Sub-status archived')
          )
        }}
      />
      <SubStatusDialog
        open={!!dialog}
        onOpenChange={(o) => !o && setDialog(null)}
        status={dialog?.status ?? 'new'}
        subStatus={dialog?.sub}
        colors={colors}
        nextSortOrder={dialog ? (byStatus.get(dialog.status)?.length ?? 0) : 0}
        onSaved={() => onChanged()}
      />
    </div>
  )
}
