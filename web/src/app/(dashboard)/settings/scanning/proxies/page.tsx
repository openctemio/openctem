'use client'

import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { ProxyPoolsPanel } from '@/features/proxy-pools'

/** Settings › Scanning › Proxies: send your sensors' scan traffic through proxies. */
export default function ProxiesSettingsPage() {
  const { t } = useTranslation()
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('settings.item.proxies', 'Proxies')}
          description={t(
            'proxyPools.page.description',
            "Send your own sensors' scan traffic through proxies you control. Health comes from real scan traffic: a failing proxy is set aside and tried again later, and a scan never falls back to a direct connection while a pool applies."
          )}
        />
        <ProxyPoolsPanel />
      </PageStack>
    </Main>
  )
}
