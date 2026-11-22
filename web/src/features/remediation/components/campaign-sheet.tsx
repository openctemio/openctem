'use client'

/**
 * A campaign's quick view, opened from a row of the Campaigns list
 * (`?campaign=<id>`): status, owner, due date, findings fixed, its first tasks
 * and the status change it allows, under the same gates as the campaign page
 * (findings remediation write and the campaign's can_edit). Editing, the Jira
 * epic, adding or removing tasks and deleting stay on the full page.
 */

import { useState } from 'react'
import { Lock, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { ApiClientError } from '@/lib/api/error-handler'
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
import { StatusChip } from '@/features/shared/components/status-chip'
import { useTasks, useRevalidateHub } from '@/features/remediation-hub/api/use-remediation-hub'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import { DeadlinePill, TaskStatePill } from '@/features/remediation-hub/components/task-bits'
import type { SheetListPosition } from '@/features/remediation-hub/components/task-sheet'
import { rowFocusTarget } from '@/hooks/use-sheet-param'
import {
  campaignApi,
  type RemediationCampaign,
  useRemediationCampaign,
  useRevalidateCampaigns,
} from '../api/use-remediation-campaigns'
import { CampaignDue, CampaignTasksCell, FindingsProgress } from './campaign-bits'
import { CampaignStatusAction, type CampaignStatusChange } from './campaign-status-action'

/** Tasks listed in the sheet; the rest are on the full page. */
export const SHEET_TASKS = 8

export function CampaignSheet({
  campaignId,
  onClose,
  position,
}: {
  campaignId: string | null
  onClose: () => void
  position?: SheetListPosition
}) {
  const { t } = useTranslation()
  const href = campaignId ? `/remediation/campaigns/${campaignId}` : ''
  return (
    <DetailSheet
      open={!!campaignId}
      onOpenChange={(o) => {
        if (!o) onClose()
      }}
      width="xl"
      returnFocus={() => rowFocusTarget(campaignId, href)}
      header={
        campaignId ? (
          <CampaignSheetHeader key={campaignId} campaignId={campaignId} onClose={onClose} />
        ) : null
      }
    >
      {campaignId && <CampaignSheetBody key={campaignId} campaignId={campaignId} />}
      {campaignId && (
        <DetailSheetFooter className="flex items-center justify-between gap-3">
          {position ? (
            <DetailPosition
              label={t('common.table.shownOfTotal', undefined, {
                shown: position.index,
                total: position.total,
              })}
              onPrev={position.prevId ? () => position.onGo(position.prevId!) : undefined}
              onNext={position.nextId ? () => position.onGo(position.nextId!) : undefined}
              prevLabel={t('remediationCampaigns.sheet.prev')}
              nextLabel={t('remediationCampaigns.sheet.next')}
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

function CampaignSheetHeader({ campaignId, onClose }: { campaignId: string; onClose: () => void }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const { data: c, mutate } = useRemediationCampaign(campaignId)
  const revalidateCampaigns = useRevalidateCampaigns()
  const revalidateHub = useRevalidateHub()
  const [busy, setBusy] = useState(false)
  const [confirmCancel, setConfirmCancel] = useState(false)
  const writable = !!c && hasPermission(Permission.RemediationWrite) && c.can_edit

  const setStatus = async (status: CampaignStatusChange, success: string) => {
    if (!c) return false
    setBusy(true)
    try {
      const next = await campaignApi.setStatus(c.id, { status, version: c.version })
      void mutate(next as RemediationCampaign, { revalidate: false })
      void revalidateCampaigns()
      void revalidateHub()
      toast.success(success)
      return true
    } catch (err) {
      if (err instanceof ApiClientError && err.statusCode === 409) void mutate()
      toast.error(
        err instanceof ApiClientError && err.message
          ? err.message
          : t('remediationCampaigns.toast.failed')
      )
      return false
    } finally {
      setBusy(false)
    }
  }
  const open = c?.status === 'draft' || c?.status === 'active'

  return (
    <>
      <DetailHeader
        title={c?.name ?? t('remediationCampaigns.sheet.loading')}
        badges={c ? <StatusChip domain="remediationCampaign" value={c.status} /> : undefined}
        actions={
          writable && c ? (
            <CampaignStatusAction
              campaign={c}
              busy={busy}
              onSetStatus={(status, success) => void setStatus(status, success)}
            />
          ) : undefined
        }
        menu={
          writable && open
            ? [
                {
                  label: t('remediationCampaigns.actions.cancelCampaign'),
                  icon: XCircle,
                  destructive: true,
                  onSelect: () => setConfirmCancel(true),
                },
              ]
            : undefined
        }
        onClose={onClose}
      />
      {c && (
        <ConfirmDialog
          open={confirmCancel}
          onOpenChange={(o) => !o && setConfirmCancel(false)}
          title={t('remediationCampaigns.confirm.cancelTitle', undefined, { name: c.name })}
          desc={t('remediationCampaigns.confirm.cancelDesc')}
          confirmText={t('remediationCampaigns.actions.cancelCampaign')}
          cancelBtnText={t('remediationCampaigns.actions.keep')}
          destructive
          isLoading={busy}
          handleConfirm={async () => {
            if (await setStatus('canceled', t('remediationCampaigns.toast.canceled')))
              setConfirmCancel(false)
          }}
        />
      )}
    </>
  )
}

function CampaignSheetBody({ campaignId }: { campaignId: string }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const owners = useOwnerNames()
  const { data: c, error, isLoading, mutate } = useRemediationCampaign(campaignId)

  if (error) {
    return (
      <ErrorState
        title={t('remediationCampaigns.detail.loadError')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !c) {
    return (
      <div className="space-y-3 p-4 sm:p-6" aria-busy="true">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }
  const teamName = owners.group(c.assigned_team)
  return (
    <DetailSections>
      <DetailSection title={t('remediationCampaigns.sheet.status')}>
        {c.description && (
          <p className="text-meta mb-3 break-words whitespace-pre-line">{c.description}</p>
        )}
        <DetailFieldGrid>
          <DetailField label={t('remediationCampaigns.columns.owner')}>
            {owners.user(c.assigned_to) ?? t('remediationCampaigns.owner.unassigned')}
            {teamName && <span className="text-meta block">{teamName}</span>}
          </DetailField>
          <DetailField label={t('remediationCampaigns.columns.due')}>
            <CampaignDue campaign={c} relative />
          </DetailField>
          <DetailField label={t('remediationCampaigns.columns.progress')}>
            <FindingsProgress summary={c.summary} className="max-w-48" />
          </DetailField>
          <DetailField label={t('remediationCampaigns.columns.tasks')}>
            <CampaignTasksCell summary={c.summary} />
          </DetailField>
        </DetailFieldGrid>
        {hasPermission(Permission.RemediationWrite) && !c.can_edit && (
          <p className="text-meta mt-3 flex items-center gap-2">
            <Lock className="size-4" aria-hidden />
            {t('remediationCampaigns.detail.readOnly')}
          </p>
        )}
      </DetailSection>
      <CampaignSheetTasks campaign={c} />
    </DetailSections>
  )
}

function CampaignSheetTasks({ campaign: c }: { campaign: RemediationCampaign }) {
  const { t } = useTranslation()
  const { data, error, mutate } = useTasks({
    campaignId: c.id,
    sort: 'deadline',
    page: 1,
    perPage: SHEET_TASKS,
  })
  const tasks = data?.data ?? []
  const total = data?.total ?? c.summary.tasks
  return (
    <DetailSection title={t('remediationCampaigns.detail.tasks', undefined, { count: total })}>
      {error ? (
        <ErrorState
          title={t('remediationCampaigns.sheet.tasksError')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : !data ? (
        <Skeleton className="h-24 w-full" />
      ) : tasks.length === 0 ? (
        <p className="text-meta">{t('remediationCampaigns.sheet.noTasks')}</p>
      ) : (
        <ul className="divide-y" data-testid="campaign-sheet-tasks">
          {tasks.map((task) => (
            <li key={task.id} className="flex min-w-0 items-center gap-2 py-2">
              <Link
                href={`/remediation/tasks/${task.id}`}
                className="min-w-0 flex-1 truncate text-sm font-medium hover:underline"
                title={task.title}
              >
                {task.title}
              </Link>
              <TaskStatePill state={task.state} className="shrink-0" />
              <span className="shrink-0">
                <DeadlinePill task={task} />
              </span>
            </li>
          ))}
        </ul>
      )}
      {total > tasks.length && tasks.length > 0 && (
        <p className="text-meta mt-2">
          <Link href={`/remediation/campaigns/${c.id}`} className="underline">
            {t('remediationCampaigns.sheet.moreTasks', undefined, { n: total - tasks.length })}
          </Link>
        </p>
      )}
    </DetailSection>
  )
}
