'use client'

/**
 * Settings > Content catalog (api/docs/architecture/content-catalog.md):
 * browse the signed catalog, install and update packages, decide requests
 * and set the approval option. The API is the authority for every action;
 * the page only hides what the member's permissions cannot do.
 */

import { useCallback, useState } from 'react'
import { useSWRConfig } from 'swr'
import { Main } from '@/components/layout'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader } from '@/features/shared'
import {
  ApprovalSettings,
  CatalogTab,
  CONTENT_API,
  InstalledTab,
  PackageSheet,
  RequestsTab,
  TrustBanner,
  useContentRequests,
  useContentTrust,
} from '@/features/content-catalog'
import { useTranslation } from '@/context/i18n-provider'
import { useHashTab } from '@/hooks/use-hash-tab'

const TABS = ['catalog', 'installed', 'requests', 'settings'] as const

export default function ContentCatalogPage() {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()
  const [rawTab, setTab] = useHashTab('catalog')
  const tab = (TABS as readonly string[]).includes(rawTab) ? rawTab : 'catalog'
  const [open, setOpen] = useState<string | null>(null)
  const trust = useContentTrust()
  const requests = useContentRequests()
  const pending = (requests.data ?? []).filter((r) => r.status === 'pending').length

  // Any change can move the catalog list, the installations and the requests.
  const refreshAll = useCallback(() => {
    void mutate((key) => typeof key === 'string' && key.startsWith(CONTENT_API))
  }, [mutate])

  return (
    <Main>
      <PageHeader
        title={t('settings.item.content', 'Content catalog')}
        description={t(
          'contentCatalog.pageDescription',
          'Signed packages of rules, templates and other content. Installing one makes it available to the whole organization.'
        )}
      />
      <div className="space-y-4">
        <TrustBanner trust={trust.data} />
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="catalog">{t('contentCatalog.tab.catalog', 'Catalog')}</TabsTrigger>
            <TabsTrigger value="installed">
              {t('contentCatalog.tab.installed', 'Installed')}
            </TabsTrigger>
            <TabsTrigger value="requests">
              {t('contentCatalog.tab.requests', 'Requests')}
              {pending > 0 && <TabsCount value={pending} />}
            </TabsTrigger>
            <TabsTrigger value="settings">
              {t('contentCatalog.tab.settings', 'Settings')}
            </TabsTrigger>
          </TabsList>
          <TabsContent value="catalog">
            <CatalogTab onOpen={setOpen} />
          </TabsContent>
          <TabsContent value="installed">
            <InstalledTab onOpen={setOpen} />
          </TabsContent>
          <TabsContent value="requests">
            <RequestsTab onOpen={setOpen} onChanged={refreshAll} />
          </TabsContent>
          <TabsContent value="settings">
            <ApprovalSettings />
          </TabsContent>
        </Tabs>
      </div>
      <PackageSheet packageId={open} onClose={() => setOpen(null)} onChanged={refreshAll} />
    </Main>
  )
}
