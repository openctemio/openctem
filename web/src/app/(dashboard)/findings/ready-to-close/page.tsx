'use client'

import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared/components/page-header'
import { PageStack } from '@/features/shared/components/page-stack'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useListParams } from '@/hooks/use-list-params'
import { usePermissions, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'
import { AutoClosedList, ReadyToCloseList, useReadyToCloseCount } from '@/features/closure-review'

/**
 * Findings > Ready to close: closes waiting for a person, and what the
 * platform closed by itself in the last 7 days
 * (api/docs/architecture/finding-verification-plan.md, "Ready to close").
 */
export default function ReadyToClosePage() {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const list = useListParams({ filters: { view: '' } })
  const view: 'ready' | 'auto_closed' =
    list.filters.view === 'auto_closed' ? 'auto_closed' : 'ready'
  const readyCount = useReadyToCloseCount(can(Permission.FindingsVerify))
  const changeView = (v: string) => list.setFilter('view', v === 'auto_closed' ? v : '')
  const listProps = {
    page: list.page,
    perPage: list.perPage,
    pagination: list.pagination,
    onPaginationChange: list.setPagination,
  }

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('findings.closureReview.title', 'Ready to close')}
          description={t(
            'findings.closureReview.description',
            'Findings a covered scan no longer finds. Blocked, unreachable or partial scans never put a finding here.'
          )}
        />
        <Tabs value={view} onValueChange={changeView}>
          <TabsList aria-label={t('findings.closureReview.viewLabel', 'Closes')}>
            <TabsTrigger value="ready">
              {t('findings.closureReview.tabReady', 'Ready to close')}
              <TabsCount value={readyCount || null} />
            </TabsTrigger>
            <TabsTrigger value="auto_closed">
              {t('findings.closureReview.tabAutoClosed', 'Recently auto-closed')}
            </TabsTrigger>
          </TabsList>
          <TabsContent value={view}>
            {view === 'ready' ? (
              <ReadyToCloseList {...listProps} />
            ) : (
              <AutoClosedList {...listProps} />
            )}
          </TabsContent>
        </Tabs>
      </PageStack>
    </Main>
  )
}
