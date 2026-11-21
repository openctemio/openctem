'use client'

import { useTranslation } from '@/context/i18n-provider'
import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useMFAFloor } from '@console/features/admin-console/api/use-platform-settings'
import { MFAFloorForm } from '@console/features/admin-console/components/mfa-floor-form'
import { adminHas } from '@console/features/admin-console/types'

/** Settings -> Two-factor: the lowest two-factor requirement of every organization. */
export default function TwoFactorFloorPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useMFAFloor()
  const canEdit = adminHas(me, 'platform.settings.mfa')
  return (
    <SettingsPage
      title={t('admin.nav.twoFactor', 'Two-factor')}
      description={t(
        'admin.mfaFloor.pageDescription',
        'The two-factor rule every organization starts from.'
      )}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
      readOnly={
        !canEdit &&
        t('admin.settings.superAdminOnly', 'Only a super admin can change this setting.')
      }
    >
      {data && <MFAFloorForm settings={data} canEdit={canEdit} onSaved={() => void mutate()} />}
    </SettingsPage>
  )
}
