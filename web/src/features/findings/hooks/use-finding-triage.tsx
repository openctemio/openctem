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

import { useEffect, useState, type ReactNode } from 'react'
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
import {
  FINDING_STATUS_CONFIG,
  SEVERITY_CONFIG,
  requiresApproval,
  type FindingStatus,
  type FindingUser,
} from '../types'

export interface FindingTriageTarget {
  id: string
  status: FindingStatus
  severity: Severity
  assignee?: FindingUser
}

export interface UseFindingTriageOptions {
  onStatusChange?: (status: FindingStatus) => void
  onSeverityChange?: (severity: Severity) => void
  onAssigneeChange?: (assignee: FindingUser | null) => void
}

export function useFindingTriage(finding: FindingTriageTarget, opts: UseFindingTriageOptions = {}) {
  const [status, setStatus] = useState<FindingStatus>(finding.status)
  const [severity, setSeverity] = useState<Severity>(finding.severity)
  const [assignee, setAssignee] = useState<FindingUser | undefined>(finding.assignee)
  const [approvalTarget, setApprovalTarget] = useState<FindingStatus | null>(null)

  // Follow the server after a revalidation or when another finding is shown.
  //
  // The parent rebuilds `finding` (and a fresh `assignee` object) on every
  // render, so these effects must key off STABLE PRIMITIVES and bail when the
  // value has not actually changed. Depending on the `assignee` object — or
  // calling setState unconditionally with a new object reference — re-fires the
  // effect every render, which schedules another render, and the page loops
  // ("Maximum update depth exceeded").
  const assigneeId = finding.assignee?.id ?? null
  useEffect(() => {
    setStatus((prev) => (prev === finding.status ? prev : finding.status))
  }, [finding.id, finding.status])
  useEffect(() => {
    setSeverity((prev) => (prev === finding.severity ? prev : finding.severity))
  }, [finding.id, finding.severity])
  useEffect(() => {
    // Keyed on `assigneeId` (a primitive); the current object is read through
    // the updater so a new reference with the same id does not re-fire the loop.
    setAssignee((prev) => ((prev?.id ?? null) === assigneeId ? prev : finding.assignee))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- key off assigneeId, not the object
  }, [finding.id, assigneeId])

  const { trigger: updateStatus, isMutating: statusBusy } = useUpdateFindingStatusApi(finding.id)
  const { trigger: updateSeverity, isMutating: severityBusy } = useUpdateFindingSeverityApi(
    finding.id
  )
  const { trigger: assignUser, isMutating: assigning } = useAssignFindingApi(finding.id)
  const { trigger: unassignUser, isMutating: unassigning } = useUnassignFindingApi(finding.id)

  const changeStatus = async (next: FindingStatus, isUndo = false) => {
    if (next === status) return
    if (requiresApproval(next)) {
      setApprovalTarget(next)
      return
    }
    const previous = status
    setStatus(next)
    try {
      await updateStatus({
        status: next,
        resolution: next === 'resolved' ? 'Resolved via UI' : undefined,
      })
      opts.onStatusChange?.(next)
      await invalidateFindingsCache()
      toast.success(
        `Status updated to ${FINDING_STATUS_CONFIG[next].label}`,
        isUndo
          ? { duration: 3000 }
          : {
              action: { label: 'Undo', onClick: () => void changeStatus(previous, true) },
              duration: 5000,
            }
      )
    } catch (error) {
      setStatus(previous)
      toast.error(getErrorMessage(error, 'Failed to update status'))
    }
  }

  const changeSeverity = async (next: Severity, isUndo = false) => {
    if (next === severity) return
    const previous = severity
    setSeverity(next)
    try {
      await updateSeverity({ severity: next })
      opts.onSeverityChange?.(next)
      await invalidateFindingsCache()
      toast.success(
        `Severity updated to ${SEVERITY_CONFIG[next].label}`,
        isUndo
          ? { duration: 3000 }
          : {
              action: { label: 'Undo', onClick: () => void changeSeverity(previous, true) },
              duration: 5000,
            }
      )
    } catch (error) {
      setSeverity(previous)
      toast.error(getErrorMessage(error, 'Failed to update severity'))
    }
  }

  const changeAssignee = async (next: FindingUser | null, isUndo = false) => {
    if ((next?.id ?? null) === (assignee?.id ?? null)) return
    const previous = assignee ?? null
    setAssignee(next ?? undefined)
    try {
      if (next) await assignUser({ user_id: next.id })
      else await unassignUser()
      opts.onAssigneeChange?.(next)
      await invalidateFindingsCache()
      toast.success(
        next ? `Assigned to ${next.name}` : 'Unassigned',
        isUndo
          ? { duration: 3000 }
          : {
              action: { label: 'Undo', onClick: () => void changeAssignee(previous, true) },
              duration: 5000,
            }
      )
    } catch (error) {
      setAssignee(previous ?? undefined)
      toast.error(getErrorMessage(error, next ? 'Failed to assign' : 'Failed to unassign'))
    }
  }

  // The dialog is mounted only while a status waits for approval, so it is
  // always open when rendered; closing it clears the pending status.
  const dialogs: ReactNode = approvalTarget ? (
    <ApprovalDialog
      findingId={finding.id}
      targetStatus={approvalTarget}
      open
      onOpenChange={(open) => {
        if (!open) setApprovalTarget(null)
      }}
      onSuccess={() => void invalidateFindingsCache()}
    />
  ) : null

  return {
    status,
    severity,
    assignee,
    changeStatus: (s: FindingStatus) => void changeStatus(s),
    changeSeverity: (s: Severity) => void changeSeverity(s),
    changeAssignee: (u: FindingUser | null) => void changeAssignee(u),
    statusBusy,
    severityBusy,
    assigneeBusy: assigning || unassigning,
    dialogs,
  }
}

export type FindingTriage = ReturnType<typeof useFindingTriage>
