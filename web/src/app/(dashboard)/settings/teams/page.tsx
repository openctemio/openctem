'use client'

import type { ReactNode } from 'react'
import { Main } from '@/components/layout'
import { PageHeader, PageStack } from '@/features/shared'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { TeamsSection } from '@/features/access-control/components/teams-section'
import { AssignmentRulesSection } from '@/features/access-control/components/assignment-rules-section'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useHasPermission, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

type Tab = 'teams' | 'assignment-rules'

/**
 * Teams, with the rules that assign assets to them as a second tab: the rules
 * are each team's scope definition and mean nothing without Teams. Was two
 * pages (/settings/access-control/groups and .../assignment-rules); both 308
 * here (the rules to ?tab=assignment-rules).
 */
export default function TeamsPage() {
  const { t } = useTranslation()
  const [tabParam, setTab] = useUrlFilter('tab', 'teams')
  const canSeeRules = useHasPermission(Permission.AssignmentRulesRead)
  const tab: Tab = tabParam === 'assignment-rules' && canSeeRules ? 'assignment-rules' : 'teams'

  const header = (actions: ReactNode) => (
    <>
      <PageHeader
        title={t('org.teamsPage.title', 'Teams')}
        description={
          tab === 'teams'
            ? t(
                'org.teamsPage.teamsDesc',
                'Organize members into teams to control which assets they can see. What members can do comes from their roles.'
              )
            : t(
                'org.teamsPage.rulesDesc',
                'Rules that assign assets to teams automatically, evaluated in priority order.'
              )
        }
      >
        {actions}
      </PageHeader>
      {canSeeRules && (
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="teams">{t('org.teamsPage.tabTeams', 'Teams')}</TabsTrigger>
            <TabsTrigger value="assignment-rules">
              {t('org.teamsPage.tabRules', 'Assignment rules')}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      )}
    </>
  )

  return (
    <Main>
      <PageStack>
        {tab === 'teams' ? (
          <TeamsSection header={header} />
        ) : (
          <AssignmentRulesSection header={header} />
        )}
      </PageStack>
    </Main>
  )
}
