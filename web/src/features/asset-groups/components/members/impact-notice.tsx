'use client'

/**
 * What a change to a group means for the teams and scans that use it. Shown
 * before the change is saved (preview) and after it (the answer).
 */

import { AlertTriangle } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import type { GroupRuleImpact } from '../../types'

interface ImpactNoticeProps {
  impact: GroupRuleImpact | undefined
}

export function ImpactNotice({ impact }: ImpactNoticeProps) {
  const { t } = useTranslation()
  if (!impact || (impact.teams.length === 0 && impact.scans.length === 0)) return null
  const names = (items: { name: string }[]) => items.map((i) => i.name).join(', ')
  return (
    <Alert data-testid="group-impact-notice" variant={impact.widens ? 'destructive' : 'default'}>
      <AlertTriangle className="h-4 w-4" />
      <AlertTitle>
        {impact.widens
          ? t(
              'assetGroups.members.impact.widens',
              'This brings {count} more assets into a group that is in use',
              {
                count: impact.would_join,
              }
            )
          : t('assetGroups.members.impact.inUse', 'This group is in use')}
      </AlertTitle>
      <AlertDescription className="space-y-1">
        {impact.teams.length > 0 && (
          <p>
            {t('assetGroups.members.impact.teams', 'Team access rules that name it: {names}', {
              names: names(impact.teams),
            })}
          </p>
        )}
        {impact.scans.length > 0 && (
          <p>
            {t('assetGroups.members.impact.scans', 'Scans that target it: {names}', {
              names: names(impact.scans),
            })}
          </p>
        )}
        {impact.privileged_team && (
          <p>
            {t(
              'assetGroups.members.impact.privileged',
              'A team with a privileged role uses it: only the owner can save this change, after signing in again.'
            )}
          </p>
        )}
      </AlertDescription>
    </Alert>
  )
}
