'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { useAdmin } from '@console/features/admin-console/components/admin-console-shell'
import { ScanIdentificationCard } from '@console/features/admin-console/components/scan-identification-card'
import { adminHas } from '@console/features/admin-console/types'

/**
 * System -> Scan identification: the platform layer of the User-Agent and
 * headers scans send. Any administrator sees it; changing it needs
 * platform.settings.general.write, the step-up and a reason.
 */
export default function ScanIdentificationPage() {
  const { t } = useTranslation()
  const me = useAdmin()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('admin.scanIdent.pageTitle', 'Scan identification')}
          description={t(
            'admin.scanIdent.pageDesc',
            'The User-Agent and headers every scan sends, so scanned systems recognize scan traffic from this platform.'
          )}
        />
        <ScanIdentificationCard canEdit={adminHas(me, 'platform.settings.general.write')} />
      </PageStack>
    </Main>
  )
}
