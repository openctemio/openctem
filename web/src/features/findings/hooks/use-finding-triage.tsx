'use client'

/**
 * Status, severity and assignee of one finding: optimistic local state, the
 * API writes, Undo toasts, and the approval rule — a status that needs
 * approval (false positive, accepted risk) opens the ApprovalDialog instead
 * of writing. The detail page and the findings drawer both use it, so the
 * rules cannot differ between them.
 *
 * Render `dialogs` once next to the controls.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { Severity } from '@/features/shared/types'
import {
  invalidateFindingsCache,
  useAssignFindingApi,
  useUnassignFindingApi,
  useUpdateFindingSeverityApi,
  useUpdateFindingStatusApi,
} from '../api/use-findings-api'
import { ApprovalDialog } from '../components/approval-dialog'
import type { TransitionDecision } from '../api/use-finding-transitions'
import { subStatusName, useSubStatusCatalog } from '../api/use-finding-lifecycles'
import {
  LifecycleMoveDialog,
  type LifecycleMoveInput,
} from '../components/lifecycle/lifecycle-move-dialog'
import {
  StatusNoteDialog,
  needsStatusNote,
  type NotedStatus,
} from '../components/status-note-dialog'
import {
  FINDING_STATUS_CONFIG,
  SEVERITY_CONFIG,
  requiresApproval,
  type FindingStatus,
  type FindingUser,
} from '../types'
import { useTranslation } from '@/context/i18n-provider'
import { FINDINGS_CLOSED_STATUSES } from '@/features/findings/lib/list-defaults'
import { isFindingChanged } from '@/features/findings/lib/finding-conflict'

export interface FindingTriageTarget {
  id: string
  status: FindingStatus
  severity: Severity
  assignee?: FindingUser
  /** Longest risk acceptance the API allows for this finding, in days. */
  maxAcceptanceDays?: number
  /** The organization's sub-status inside the status. */
  subStatusId?: string
  /** Version of the finding shown; writes are refused when it moved on. */
  rowVersion?: number
}

export interface UseFindingTriageOptions {
  onStatusChange?: (status: FindingStatus) => void
  onSeverityChange?: (severity: Severity) => void
  onAssigneeChange?: (assignee: FindingUser | null) => void
}

export function useFindingTriage(finding: FindingTriageTarget, opts: UseFindingTriageOptions = {}) {
  const { t, locale } = useTranslation()
  const [status, setStatus] = useState<FindingStatus>(finding.status)
  const [subStatusId, setSubStatusId] = useState<string | undefined>(finding.subStatusId)
  // A move the organization's lifecycle asks details for waits here.
  const [moveTarget, setMoveTarget] = useState<TransitionDecision | null>(null)
  const catalog = useSubStatusCatalog(!!moveTarget?.to_sub_status_id)
  const [severity, setSeverity] = useState<Severity>(finding.severity)
  const [assignee, setAssignee] = useState<FindingUser | undefined>(finding.assignee)
  const [approvalTarget, setApprovalTarget] = useState<FindingStatus | null>(null)
  // A fix claim or a resolve waits here for its note (the API requires one).
  const [noteTarget, setNoteTarget] = useState<NotedStatus | null>(null)

  // Follow the server after a revalidation or when another finding is shown.
  //
  // The parent rebuilds `finding` (and a fresh `assignee` object) on every
  // render. The effects therefore compare by VALUE and return `prev` when
  // nothing changed, so React bails out instead of scheduling another render.
  // Calling setState unconditionally with the new object reference — as this
  // used to — set a new value every render and looped ("Maximum update depth
  // exceeded"). Assignee is compared by id (the only stable identity on the
  // rebuilt object); the effect still re-runs cheaply each render, but no longer
  // re-renders.
  useEffect(() => {
    setStatus((prev) => (prev === finding.status ? prev : finding.status))
  }, [finding.id, finding.status])
  useEffect(() => {
    setSubStatusId((prev) => (prev === finding.subStatusId ? prev : finding.subStatusId))
  }, [finding.id, finding.subStatusId])
  useEffect(() => {
    setSeverity((prev) => (prev === finding.severity ? prev : finding.severity))
  }, [finding.id, finding.severity])
  useEffect(() => {
    setAssignee((prev) =>
      (prev?.id ?? null) === (finding.assignee?.id ?? null) ? prev : finding.assignee
    )
  }, [finding.id, finding.assignee])

  // The version the person decided on: sent as If-Match so a write never
  // overwrites a change someone else made since the finding was loaded. It
  // follows the loaded finding and each write's response.
  const rowVersion = useRef<number | undefined>(finding.rowVersion)
  useEffect(() => {
    rowVersion.current = finding.rowVersion
  }, [finding.id, finding.rowVersion])
  const wrote = (updated?: { row_version?: number } | null) => {
    if (updated && typeof updated.row_version === 'number') rowVersion.current = updated.row_version
  }
  // Someone else changed the finding: reload it and say so (nothing written).
  const changedMeanwhile = async (error: unknown): Promise<boolean> => {
    if (!isFindingChanged(error)) return false
    toast.info(
      t(
        'findings.conflict.changed',
        'Someone else changed this finding. It has been reloaded; check it and try again.'
      )
    )
    await invalidateFindingsCache()
    return true
  }

  const { trigger: updateStatus, isMutating: statusBusy } = useUpdateFindingStatusApi(finding.id)
  const { trigger: updateSeverity, isMutating: severityBusy } = useUpdateFindingSeverityApi(
    finding.id
  )
  const { trigger: assignUser, isMutating: assigning } = useAssignFindingApi(finding.id)
  const { trigger: unassignUser, isMutating: unassigning } = useUnassignFindingApi(finding.id)

  const changeStatus = async (
    next: FindingStatus,
    isUndo = false,
    note?: string,
    move?: TransitionDecision,
    input?: LifecycleMoveInput
  ) => {
    const toSub = move?.to_sub_status_id
    // A label change inside the status is a move too (sub-status only).
    if (next === status && (toSub ?? '') === (subStatusId ?? '')) return
    if (requiresApproval(next)) {
      setApprovalTarget(next)
      return
    }
    // The organization's lifecycle asks for a longer note or fields: one
    // dialog collects them (and the platform's note, when it needs one).
    if (
      !isUndo &&
      !input &&
      move &&
      ((move.note_min_len ?? 0) > 0 || (move.fields?.length ?? 0) > 0)
    ) {
      setMoveTarget(move)
      return
    }
    if (!isUndo && !input && note === undefined && needsStatusNote(next)) {
      setNoteTarget(next)
      return
    }
    const previous = status
    const previousSub = subStatusId
    setStatus(next)
    setSubStatusId(toSub)
    try {
      const updated = await updateStatus({
        rowVersion: rowVersion.current,
        status: next,
        resolution: input?.note ?? note,
        ...(toSub ? { sub_status_id: toSub } : {}),
        ...(input?.fields ? { fields: input.fields } : {}),
      })
      setSubStatusId(updated?.sub_status_id)
      wrote(updated)
      opts.onStatusChange?.(next)
      await invalidateFindingsCache()
      // No Undo on a closing move (resolve): reverting it is a reopen, which
      // a person makes deliberately from the status control.
      const closing = (FINDINGS_CLOSED_STATUSES as readonly string[]).includes(next)
      toast.success(
        t('findings.triage.statusUpdated', 'Status updated to {status}', {
          status: t(FINDING_STATUS_CONFIG[next].labelKey, FINDING_STATUS_CONFIG[next].label),
        }),
        isUndo || closing
          ? { duration: 3000 }
          : {
              action: {
                label: t('findings.triage.undo', 'Undo'),
                onClick: () => void changeStatus(previous, true),
              },
              duration: 5000,
            }
      )
    } catch (error) {
      setStatus(previous)
      setSubStatusId(previousSub)
      if (await changedMeanwhile(error)) return
      toast.error(
        getErrorMessage(error, t('findings.triage.statusFailed', 'Failed to update status'))
      )
    }
  }

  const changeSeverity = async (next: Severity, isUndo = false) => {
    if (next === severity) return
    const previous = severity
    setSeverity(next)
    try {
      wrote(await updateSeverity({ severity: next, rowVersion: rowVersion.current }))
      opts.onSeverityChange?.(next)
      await invalidateFindingsCache()
      toast.success(
        t('findings.triage.severityUpdated', 'Severity updated to {severity}', {
          severity: t(`severity.${next}`, SEVERITY_CONFIG[next].label),
        }),
        isUndo
          ? { duration: 3000 }
          : {
              action: {
                label: t('findings.triage.undo', 'Undo'),
                onClick: () => void changeSeverity(previous, true),
              },
              duration: 5000,
            }
      )
    } catch (error) {
      setSeverity(previous)
      if (await changedMeanwhile(error)) return
      toast.error(
        getErrorMessage(error, t('findings.triage.severityFailed', 'Failed to update severity'))
      )
    }
  }

  const changeAssignee = async (next: FindingUser | null, isUndo = false) => {
    if ((next?.id ?? null) === (assignee?.id ?? null)) return
    const previous = assignee ?? null
    setAssignee(next ?? undefined)
    try {
      if (next) wrote(await assignUser({ user_id: next.id, rowVersion: rowVersion.current }))
      else wrote(await unassignUser({ rowVersion: rowVersion.current }))
      opts.onAssigneeChange?.(next)
      await invalidateFindingsCache()
      toast.success(
        next
          ? t('findings.triage.assignedTo', 'Assigned to {name}', { name: next.name })
          : t('findings.triage.unassigned', 'Unassigned'),
        isUndo
          ? { duration: 3000 }
          : {
              action: {
                label: t('findings.triage.undo', 'Undo'),
                onClick: () => void changeAssignee(previous, true),
              },
              duration: 5000,
            }
      )
    } catch (error) {
      setAssignee(previous ?? undefined)
      if (await changedMeanwhile(error)) return
      toast.error(
        getErrorMessage(
          error,
          next
            ? t('findings.triage.assignFailed', 'Failed to assign')
            : t('findings.triage.unassignFailed', 'Failed to unassign')
        )
      )
    }
  }

  // The dialog is mounted only while a status waits for approval, so it is
  // always open when rendered; closing it clears the pending status.
  const noteDialog: ReactNode = noteTarget ? (
    <StatusNoteDialog
      status={noteTarget}
      open
      onOpenChange={(open) => {
        if (!open) setNoteTarget(null)
      }}
      onConfirm={(note) => {
        const target = noteTarget
        setNoteTarget(null)
        void changeStatus(target, false, note)
      }}
    />
  ) : null

  const moveSub = moveTarget?.to_sub_status_id
    ? catalog.get(moveTarget.to_sub_status_id)
    : undefined
  const moveDialog: ReactNode = moveTarget ? (
    <LifecycleMoveDialog
      open
      move={moveTarget}
      targetLabel={
        moveTarget.name ||
        (moveSub
          ? subStatusName(moveSub, locale)
          : t(
              FINDING_STATUS_CONFIG[moveTarget.to].labelKey,
              FINDING_STATUS_CONFIG[moveTarget.to].label
            ))
      }
      noteRequired={needsStatusNote(moveTarget.to)}
      onOpenChange={(open) => {
        if (!open) setMoveTarget(null)
      }}
      onConfirm={(input) => {
        const target = moveTarget
        setMoveTarget(null)
        void changeStatus(target.to, false, undefined, target, input)
      }}
    />
  ) : null

  const approvalDialog: ReactNode = approvalTarget ? (
    <ApprovalDialog
      findingId={finding.id}
      targetStatus={approvalTarget}
      maxAcceptanceDays={finding.maxAcceptanceDays}
      open
      onOpenChange={(open) => {
        if (!open) setApprovalTarget(null)
      }}
      onSuccess={() => void invalidateFindingsCache()}
    />
  ) : null

  const dialogs: ReactNode = (
    <>
      {approvalDialog}
      {noteDialog}
      {moveDialog}
    </>
  )

  return {
    status,
    subStatusId,
    severity,
    assignee,
    changeStatus: (s: FindingStatus, move?: TransitionDecision) =>
      void changeStatus(s, false, undefined, move),
    changeSeverity: (s: Severity) => void changeSeverity(s),
    changeAssignee: (u: FindingUser | null) => void changeAssignee(u),
    statusBusy,
    severityBusy,
    assigneeBusy: assigning || unassigning,
    dialogs,
  }
}

export type FindingTriage = ReturnType<typeof useFindingTriage>
