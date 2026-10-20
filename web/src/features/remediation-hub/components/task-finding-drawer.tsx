'use client'

/**
 * A task's finding in the shared finding drawer: same sections, status
 * rules and dialogs as the findings list, plus "n of N" and previous / next
 * through the task's findings. The finding is in the URL (`?finding=`), so
 * the view can be shared and Back closes it before leaving the task.
 */

import { useFindingApi } from '@/features/findings/api/use-findings-api'
import { FindingDetailDrawer } from '@/features/findings/components/finding-detail-drawer'
import { toFindingDetail } from '@/features/findings/lib/finding-detail'
import type { FindingStatus } from '@/features/findings/types'
import type { NavPosition } from '../lib/task-nav'

export function TaskFindingDrawer({
  taskId,
  findingId,
  position,
  onClose,
  onGo,
  onStatusChange,
}: {
  taskId: string
  findingId: string | null
  position: NavPosition
  onClose: () => void
  onGo: (findingId: string) => void
  onStatusChange: (findingId: string, status: FindingStatus) => void
}) {
  const { data: api } = useFindingApi(findingId)
  const finding = api && findingId && api.id === findingId ? toFindingDetail(api) : null
  return (
    <FindingDetailDrawer
      finding={finding}
      open={!!findingId && !!finding}
      onOpenChange={(o) => {
        if (!o) onClose()
      }}
      onStatusChange={onStatusChange}
      taskNav={{
        taskId,
        index: position.index,
        total: position.total,
        onPrev: position.prev ? () => onGo(position.prev as string) : undefined,
        onNext: position.next ? () => onGo(position.next as string) : undefined,
      }}
    />
  )
}
