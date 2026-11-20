'use client'

import type { ReactNode } from 'react'
import { SettingsPage } from '@/features/shared'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { TeamsSection } from '@/features/access-control/components/teams-section'
import { AssignmentRulesSection } from '@/features/access-control/components/assignment-rules-section'
import { replaceUrlSearch, useUrlFilter } from '@/hooks/use-url-param'
import { useHasPermission, Permission } from '@/lib/permissions'
import { useTranslation } from '@/context/i18n-provider'

type Tab = 'teams' | 'assignment-rules'

/**
 * Teams, with the rules that route new findings to them as a second tab
 * (board P4-Settings-Teams). Was two pages (/settings/access-control/groups
 * and .../assignment-rules); both 308 here (the rules to
 * ?tab=assignment-rules). Each tab keeps its own list, dialogs and state; the
 * page owns the one frame: title, description, Create action and the tabs.
 */
export default function TeamsPage() {
  const { t } = useTranslation()
  const [tabParam] = useUrlFilter('tab', 'teams')
  const canSeeRules = useHasPermission(Permission.AssignmentRulesRead)
  const tab: Tab = tabParam === 'assignment-rules' && canSeeRules ? 'assignment-rules' : 'teams'

  // A tab change starts the other list fresh: the filters, the search and an
  // open detail belong to the tab they were set on.
  const setTab = (next: string) => {
    const params = new URLSearchParams()
    if (next === 'assignment-rules') params.set('tab', next)
    replaceUrlSearch(params)
  }

  const frame = (actions: ReactNode, content: ReactNode, readOnly: boolean) => (
    <SettingsPage
      wide
      title={t('org.teamsPage.title', 'Teams')}
      description={
        tab === 'teams'
          ? t(
              'org.teamsPage.teamsDesc',
              'Organize members into teams to control which assets they can see. What members can do comes from their roles.'
            )
          : t(
              'org.teamsPage.rulesDesc',
              'Rules route new findings to teams automatically, evaluated in priority order (lower number first).'
            )
      }
      readOnly={
        readOnly
          ? t(
              'org.teamsPage.readOnly',
              'View only. Only owners and administrators can change these settings.'
            )
          : undefined
      }
      actions={actions}
    >
      {canSeeRules && (
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList aria-label={t('org.teamsPage.tabsLabel', 'Teams and rules')}>
            <TabsTrigger value="teams">{t('org.teamsPage.tabTeams', 'Teams')}</TabsTrigger>
            <TabsTrigger value="assignment-rules">
              {t('org.teamsPage.tabRules', 'Assignment rules')}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      )}
      {content}
    </SettingsPage>
  )

  return tab === 'teams' ? <TeamsSection frame={frame} /> : <AssignmentRulesSection frame={frame} />
}
