'use client'

/**
 * The status menu of one finding row in a task. The moves come from the
 * server (StatusSelect lists the finding's allowed transitions, blocked ones
 * disabled with the reason) and every choice runs the same triage rules and
 * dialogs as the finding drawer: a claim or resolve asks for its note or
 * evidence, a false positive or accepted risk becomes an approval request.
 * The finding is read when the row is first pointed at or focused, so the
 * write carries its row_version (If-Match).
 */

import { useState } from 'react'
import { useFindingApi } from '@/features/findings/api/use-findings-api'
import { StatusSelect } from '@/features/findings/components/status-select'
import { useFindingTriage } from '@/features/findings/hooks/use-finding-triage'
import type { FindingStatus } from '@/features/findings/types'
import type { Severity } from '@/features/shared/types'
import type { TaskMember } from '../api/types'

export function TaskRowStatus({
  member,
  onChanged,
}: {
  member: TaskMember
  onChanged: (findingId: string, status: FindingStatus) => void
}) {
  const [armed, setArmed] = useState(false)
  const { data: api } = useFindingApi(armed ? member.finding_id : null)
  const triage = useFindingTriage(
    {
      id: member.finding_id,
      status: member.status as FindingStatus,
      severity: member.severity as Severity,
      subStatusId: api?.sub_status_id ?? undefined,
      rowVersion: api?.row_version,
    },
    { onStatusChange: (s) => onChanged(member.finding_id, s) }
  )
  return (
    <span
      onPointerEnter={() => setArmed(true)}
      onFocusCapture={() => setArmed(true)}
      onClick={(e) => e.stopPropagation()}
    >
      <StatusSelect
        findingId={member.finding_id}
        value={triage.status}
        subStatusId={triage.subStatusId}
        allowSubStatusMoves
        onChange={triage.changeStatus}
        loading={triage.statusBusy}
      />
      {triage.dialogs}
    </span>
  )
}
