'use client'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { SecurityKeysPanel } from '@console/features/admin-console/components/security-keys-panel'

/** Security > My security keys: every administrator's own keys and recovery codes. */
export default function AdminSecurityKeysPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageHeader
        title={t('admin.keys.title', 'My security keys')}
        description={t(
          'admin.keys.description',
          'Security keys and passkeys are the preferred way to sign in to this console and to confirm sensitive actions.'
        )}
      />
      <div className="mt-5 max-w-3xl">
        <SecurityKeysPanel />
      </div>
    </Main>
  )
}
