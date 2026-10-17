'use client'

import { Suspense } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { HubPage } from '@/features/remediation-hub/components/hub-page'
import { TasksView } from '@/features/remediation-hub/components/tasks-view'

export default function RemediationTasksPage() {
  const { t } = useTranslation()
  return (
    <HubPage
      title={t('remediationHub.tasks.title')}
      description={t('remediationHub.tasks.description')}
    >
      <Suspense>
        <TasksView />
      </Suspense>
    </HubPage>
  )
}
