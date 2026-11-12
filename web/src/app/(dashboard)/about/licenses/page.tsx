'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { OpenSourceLicenses, type NoticeSource } from '@/features/about'
import { PageHeader, PageStack } from '@/features/shared'
import { get } from '@/lib/api/client'
import { API_NOTICES_PATH, WEB_NOTICES_PATH } from '@/lib/notices/types'

const api: NoticeSource = { id: 'api', load: () => get<unknown>(API_NOTICES_PATH) }
const web: NoticeSource = {
  id: 'web',
  load: async () => {
    const res = await fetch(WEB_NOTICES_PATH, { credentials: 'same-origin' })
    if (!res.ok) throw new Error(String(res.status))
    return res.json()
  },
}

/**
 * About > Open-source licenses (tenant app): the third-party components of
 * the API and the web app, any signed-in user. Always present, whatever the
 * brand (server/docs/architecture/third-party-notices.md).
 */
export default function OpenSourceLicensesPage() {
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
