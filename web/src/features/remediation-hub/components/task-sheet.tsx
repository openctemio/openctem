'use client'

/**
 * A task's quick view, opened from a row of the Tasks list (`?task=<id>`):
 * where it stands (state, owner, deadline, progress, risk points), its first
 * findings, and the same actions as the task page under the same gates. The
 * timeline and the query it came from load only when the person expands them;
 * deep work (moving and splitting findings) stays on the full page.
 */

import { useCallback, useState } from 'react'
import { ChevronDown, EyeOff } from 'lucide-react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { TextLink } from '@/components/ui/text-link'
import {
  DetailHeader,
  DetailSheet,
  DetailSheetFooter,
} from '@/features/shared/components/detail-sheet-layout'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
} from '@/features/shared/components/detail-sheet'
import { DetailPosition } from '@/features/shared/components/detail/detail-position'
import { ErrorState } from '@/features/shared/components/error-state'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import { rowFocusTarget } from '@/hooks/use-sheet-param'
import type { RemediationTask } from '../api/types'
import { useRevalidateHub, useTask, useTaskMembers } from '../api/use-remediation-hub'
import { useOwnerLabels } from '../api/use-owner-names'
import { DeadlinePill, TaskCampaignLink, TaskProgressCell, TaskStatePill } from './task-bits'
import { TaskHistory } from './task-history'
import { useTaskActions } from './use-task-actions'

/** Findings listed in the sheet; the rest are on the full page. */
export const SHEET_MEMBERS = 8

export interface SheetListPosition {
  /** 1-based place in the whole list. */
  index: number
  total: number
  prevId?: string
  nextId?: string
  onGo: (id: string) => void
}

export function TaskSheet({
  taskId,
  onClose,
  position,
}: {
  taskId: string | null
  onClose: () => void
  position?: SheetListPosition
}) {
  const { t } = useTranslation()
  const href = taskId ? `/remediation/tasks/${taskId}` : ''
  return (
    <DetailSheet
      open={!!taskId}
      onOpenChange={(o) => {
        if (!o) onClose()
      }}
      width="xl"
      returnFocus={() => rowFocusTarget(taskId, href)}
      header={taskId ? <TaskSheetHeader key={taskId} taskId={taskId} onClose={onClose} /> : null}
    >
      {taskId && <TaskSheetBody key={taskId} taskId={taskId} />}
      {taskId && (
        <DetailSheetFooter className="justify-between">
          {position ? (
            <DetailPosition
              label={t('common.table.shownOfTotal', undefined, {
                shown: position.index,
                total: position.total,
              })}
              onPrev={position.prevId ? () => position.onGo(position.prevId!) : undefined}
              onNext={position.nextId ? () => position.onGo(position.nextId!) : undefined}
              prevLabel={t('remediationHub.sheet.prev')}
              nextLabel={t('remediationHub.sheet.next')}
            />
          ) : (
            <span />
          )}
          <TextLink href={href}>{t('common.openFullPage')}</TextLink>
        </DetailSheetFooter>
      )}
    </DetailSheet>
  )
}

function useSheetTask(taskId: string) {
  const { data: task, error, isLoading, mutate } = useTask(taskId)
  const revalidate = useRevalidateHub()
  const refresh = useCallback(async () => {
    await Promise.all([mutate(), revalidate()])
  }, [mutate, revalidate])
  return { task, error, isLoading, mutate, refresh }
}

function TaskSheetHeader({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const { t } = useTranslation()
  const { task, refresh } = useSheetTask(taskId)
  const actions = useTaskActions(task, refresh)
  return (
    <>
      <DetailHeader
        title={task?.title ?? t('remediationHub.sheet.loading')}
        badges={task ? <TaskStatePill state={task.state} /> : undefined}
        meta={
          task?.action_title && task.action_title.trim() !== task.title.trim()
            ? [task.action_title]
            : undefined
        }
        actions={actions.primary}
        menu={actions.menu}
        onClose={onClose}
      />
      {actions.dialogs}
    </>
  )
}

function TaskSheetBody({ taskId }: { taskId: string }) {
  const { t } = useTranslation()
  const { task, error, isLoading, mutate } = useSheetTask(taskId)
  const owners = useOwnerLabels([task?.assignee_user_id], [task?.assignee_group_id])
  const [historyOpen, setHistoryOpen] = useState(false)

  if (error) {
    return (
      <ErrorState
        title={t('remediationHub.detail.loadError')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !task) {
    return (
      <div className="space-y-3 p-4 sm:p-6" aria-busy="true">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }
  const owner =
    [owners.user(task.assignee_user_id), owners.group(task.assignee_group_id)]
      .filter(Boolean)
      .join(', ') || t('remediationHub.owner.unassigned')

  return (
    <DetailSections>
      <DetailSection title={t('remediationHub.sheet.status')}>
        <DetailFieldGrid>
          <DetailField label={t('remediationHub.tasks.columns.owner')}>{owner}</DetailField>
          <DetailField label={t('remediationHub.tasks.columns.deadline')}>
            <DeadlinePill task={task} />
          </DetailField>
          <DetailField label={t('remediationHub.tasks.columns.progress')}>
            <TaskProgressCell task={task} className="max-w-48" />
          </DetailField>
          <DetailField label={t('remediationHub.tasks.columns.risk')}>
            <span className="tabular-nums" title={t('remediationHub.risk.explain')}>
              {task.counts.risk_points}
            </span>
          </DetailField>
        </DetailFieldGrid>
        {task.state_note && <p className="text-meta mt-3">{task.state_note}</p>}
        {task.campaign_id && <TaskCampaignLink campaignId={task.campaign_id} />}
        {task.hidden_members > 0 && (
          <p className="text-warning mt-3 flex items-center gap-2 text-sm">
            <EyeOff className="size-4" aria-hidden />
            {t('remediationHub.detail.hidden', undefined, { n: task.hidden_members })}
          </p>
        )}
      </DetailSection>

      <TaskSheetFindings task={task} />

      <DetailSection title={t('remediationHub.detail.timeline')}>
        {historyOpen ? (
          <TaskHistory task={task} writable={false} onChanged={() => void mutate()} />
        ) : (
          <Button variant="outline" onClick={() => setHistoryOpen(true)}>
            <ChevronDown className="size-4" aria-hidden />
            {t('remediationHub.sheet.showHistory')}
          </Button>
        )}
      </DetailSection>
    </DetailSections>
  )
}

function TaskSheetFindings({ task }: { task: RemediationTask }) {
  const { t } = useTranslation()
  const { data, error, mutate } = useTaskMembers(task.id, 1, SHEET_MEMBERS)
  const total = data?.total ?? task.counts.total
  const items = data?.data ?? []
  return (
    <DetailSection title={t('remediationHub.detail.findings', undefined, { n: total })}>
      {error ? (
        <ErrorState
          title={t('remediationHub.detail.membersError')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : !data ? (
        <Skeleton className="h-24 w-full" />
      ) : items.length === 0 ? (
        <p className="text-meta">{t('remediationHub.detail.noFindings')}</p>
      ) : (
        <ul className="divide-y" data-testid="task-sheet-findings">
          {items.map((m) => (
            <li key={m.finding_id} className="flex min-w-0 items-center gap-2 py-2">
              <SeverityBadge severity={m.severity} className="shrink-0" />
              <div className="min-w-0 flex-1">
                <Link
                  href={`/findings/${m.finding_id}`}
                  className="block truncate text-sm font-medium hover:underline"
                  title={m.title}
                >
                  {m.title}
                </Link>
                {m.asset_name && <p className="text-meta truncate">{m.asset_name}</p>}
              </div>
              <span className="text-meta shrink-0">
                {t(`remediationHub.findingStatus.${m.status}`, m.status)}
              </span>
            </li>
          ))}
        </ul>
      )}
      {total > items.length && items.length > 0 && (
        <p className="text-meta mt-2">
          <Link href={`/remediation/tasks/${task.id}`} className="underline">
            {t('remediationHub.sheet.moreFindings', undefined, { n: total - items.length })}
          </Link>
        </p>
      )}
    </DetailSection>
  )
}
