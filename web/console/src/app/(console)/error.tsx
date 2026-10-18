'use client'

import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import { Main } from '@/components/layout'

export default function AdminConsoleError({ error, reset }: { error: Error; reset: () => void }) {
  const { t } = useTranslation()

  return (
    <Main>
      <ErrorState
        title={t('admin.rootError.thisPage', 'this page')}
        error={error}
        onRetry={reset}
      />
    </Main>
  )
}
