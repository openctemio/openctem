'use client'

import { SettingsPage } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { useSignupPolicy } from '@console/features/admin-console/api/use-signup-policy'
import { SignupPolicyForm } from '@console/features/admin-console/components/signup-policy-form'
import { adminHas } from '@console/features/admin-console/types'
import { useTranslation } from '@/context/i18n-provider'

/**
 * System -> Sign-up: who may create an organization on this deployment. Any
 * administrator sees it; super admins change it (the form says so itself).
 */
export default function SignupPolicyPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  const { data, error, isLoading, mutate } = useSignupPolicy()

  return (
    <SettingsPage
      title={t('admin.signup.pageTitle')}
      description={t('admin.signup.pageDesc')}
      state={error ? 'error' : isLoading || !data ? 'loading' : 'ready'}
      error={error}
      onRetry={() => void mutate()}
    >
      {data && (
        <SignupPolicyForm
          policy={data}
          canEdit={adminHas(me, 'platform.settings.signup.write')}
          onSaved={() => void mutate()}
        />
      )}
    </SettingsPage>
  )
}
