'use client'

import { useParams } from 'next/navigation'
import { Main } from '@/components/layout'
import { TaskDetail } from '@/features/remediation-hub/components/task-detail'

export default function RemediationTaskPage() {
  const params = useParams()
  const id = params.id as string
  return (
    <Main>
      <TaskDetail taskId={id} />
    </Main>
  )
}
