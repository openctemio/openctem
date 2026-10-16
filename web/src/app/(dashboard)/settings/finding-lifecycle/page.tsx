'use client'

import { Main } from '@/components/layout'
import { FindingLifecycleSettings } from '@/features/findings/components/lifecycle/finding-lifecycle-settings'
import { PageHeader } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'

/** Settings > Finding lifecycle (api/docs/rfcs/RFC-110-tenant-lifecycles.md). */
export default function FindingLifecycleSettingsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('settings.item.finding-lifecycle', 'Finding lifecycle')}
        description={t(
          'settings.desc.finding-lifecycle',
          'Your own sub-statuses, moves and the requirements each move needs.'
        )}
      />
      <div className="mt-5">
        <FindingLifecycleSettings />
      </div>
    </Main>
  )
}
