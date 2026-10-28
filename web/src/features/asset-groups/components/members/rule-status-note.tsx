'use client'

/** How the last evaluation of a group's rule went, when it needs attention. */

import { AlertTriangle, Info } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { useTranslation } from '@/context/i18n-provider'
import { ruleStatusNeedsAttention } from '../../lib/group-rule'
import type { GroupRule } from '../../types'

export function RuleStatusNote({ rule }: { rule: GroupRule }) {
  const { t } = useTranslation()
  if (ruleStatusNeedsAttention(rule.status)) {
    return (
      <Alert variant="destructive" data-testid="rule-status-note">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          {rule.status === 'paused'
            ? t(
                'assetGroups.members.status.paused',
                'The rule is paused: the person who saved it no longer has access. The members stay as they were. Save the rule again to resume it.'
              )
            : t(
                'assetGroups.members.status.overCap',
                'The rule now matches more than {cap} assets, so the members stay as they were. Narrow the rule to resume it.',
                { cap: rule.cap.toLocaleString() }
              )}
        </AlertDescription>
      </Alert>
    )
  }
  if (rule.excluded > 0) {
    return (
      <Alert data-testid="rule-status-note">
        <Info className="h-4 w-4" />
        <AlertDescription>
          {t(
            'assetGroups.members.status.excluded',
            '{count} assets were taken out by hand and stay out while the rule matches them.',
            { count: rule.excluded }
          )}
        </AlertDescription>
      </Alert>
    )
  }
  return null
}
