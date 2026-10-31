'use client'

import { Main } from '@/components/layout'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useMFAFloor } from '@console/features/admin-console/api/use-platform-settings'
import { MFAFloorForm } from '@console/features/admin-console/components/mfa-floor-form'
import { adminHas } from '@console/features/admin-console/types'

/** Settings -> Two-factor: the lowest two-factor requirement of every organization. */
export default function TwoFactorFloorPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useMFAFloor()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.nav.twoFactor', 'Two-factor')}
          description={t(
            'admin.mfaFloor.pageDescription',
            'The two-factor rule every organization starts from.'
          )}
        />
        {error ? (
          <ErrorState
            title={t('admin.mfaFloor.errorTitle', 'the two-factor floor')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading || !data ? (
          <Skeleton className="h-96 w-full" />
        ) : (
          <MFAFloorForm
            settings={data}
            canEdit={adminHas(me, 'platform.settings.mfa')}
            onSaved={() => void mutate()}
          />
        )}
      </PageStack>
    </Main>
  )
}
