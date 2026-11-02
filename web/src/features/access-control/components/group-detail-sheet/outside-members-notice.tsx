'use client'

/**
 * Why a team cannot carry full data access, said before anyone tries: the
 * team has members outside the organization (or service accounts), and
 * those get full data access only through a role given to them directly
 * (api RFC-058, TEAM_EXTERNAL_FULL_DATA). The API refuses either way; this
 * names the people and offers the ways forward.
 */

import type { ReactNode } from 'react'
import { ShieldAlert } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { OutsideMember } from '../../types'

const NAMES_SHOWN = 3

export function outsideMemberNames(
  members: OutsideMember[],
  t: (key: string, fallback?: string, params?: Record<string, string | number>) => string
): string {
  const named = members.slice(0, NAMES_SHOWN).map((m) => {
    const name = m.name || t('org.teamOutside.unnamed', 'Unnamed member')
    return m.service ? t('org.teamOutside.serviceName', '{name} (service account)', { name }) : name
  })
  const rest = members.length - named.length
  return rest > 0
    ? t('org.teamOutside.namesMore', '{names} and {count} more', {
        names: named.join(', '),
        count: rest,
      })
    : named.join(', ')
}

export function OutsideMembersNotice({
  members,
  onShowMembers,
  onCreateTeam,
  grantAction,
}: {
  members: OutsideMember[]
  /** Opens the Members tab showing only the outside members. */
  onShowMembers?: () => void
  /** Starts a new team, for the people inside the organization. */
  onCreateTeam?: () => void
  /** Gives the role to chosen people directly instead of through the team. */
  grantAction?: ReactNode
}) {
  const { t } = useTranslation()
  if (members.length === 0) return null
  return (
    <Alert data-testid="team-outside-notice">
      <ShieldAlert className="h-4 w-4" aria-hidden />
      <AlertTitle>{t('org.teamOutside.title', 'No full data access through this team')}</AlertTitle>
      <AlertDescription className="space-y-2">
        <p>
          {t(
            'org.teamOutside.body',
            'Outside your organization: {names}. They get full data access only from a role given to them directly.',
            { names: outsideMemberNames(members, t) }
          )}
        </p>
        <div className="flex flex-wrap gap-2">
          {onShowMembers && (
            <Button size="sm" variant="outline" onClick={onShowMembers}>
              {t('org.teamOutside.show', 'Show them')}
            </Button>
          )}
          {onCreateTeam && (
            <Button size="sm" variant="outline" onClick={onCreateTeam}>
              {t('org.teamOutside.newTeam', 'New team without them')}
            </Button>
          )}
          {grantAction}
        </div>
      </AlertDescription>
    </Alert>
  )
}
