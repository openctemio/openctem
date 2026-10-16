'use client'

/** The frame of every remediation page: title, description and the section tabs. */

import type { ReactNode } from 'react'
import { Main } from '@/components/layout'
import { PageHeader, SectionTabs } from '@/features/shared'
import { REMEDIATION_SECTION_TABS } from '@/config/section-tabs'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { useSuggestionStats } from '../api/use-remediation-hub'

export function HubPage({
  title,
  description,
  actions,
  children,
}: {
  title: string
  description: string
  actions?: ReactNode
  children: ReactNode
}) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const { data: stats } = useSuggestionStats(hasPermission(Permission.RemediationRead))
  return (
    <Main>
      <PageHeader title={title} description={description}>
        {actions}
      </PageHeader>
      <SectionTabs
        tabs={REMEDIATION_SECTION_TABS}
        className="mt-4"
        label={t('remediationHub.tabsLabel')}
        counts={{ '/remediation/suggestions': stats?.proposed }}
      />
      {children}
    </Main>
  )
}
