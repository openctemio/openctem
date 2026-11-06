'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { OpenSourceLicenses, type NoticeSource } from '@/features/about'
import { PageHeader, PageStack } from '@/features/shared'
import { ADMIN_API_NOTICES_PATH, CONSOLE_WEB_NOTICES_PATH } from '@/lib/notices/types'
import { adminFetch } from '@console/lib/admin-api/client'

const api: NoticeSource = { id: 'api', load: () => adminFetch<unknown>(ADMIN_API_NOTICES_PATH) }
// Served by the console itself (console/src/app/api/v1/admin/web-licenses).
const web: NoticeSource = { id: 'web', load: () => adminFetch<unknown>(CONSOLE_WEB_NOTICES_PATH) }

/**
 * About > Open-source licenses (platform console): the third-party components
 * of the API and the console build, any administrator. Always present,
 * whatever the brand (server/docs/architecture/third-party-notices.md).
 */
export default function ConsoleOpenSourceLicensesPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('help.licenses.title', 'Open-source licenses')}
          description={t(
            'help.licenses.description',
            'The open-source components this build is made of, with their licenses. The list is generated when the release is built.'
          )}
        />
        <OpenSourceLicenses api={api} web={web} />
      </PageStack>
    </Main>
  )
}
