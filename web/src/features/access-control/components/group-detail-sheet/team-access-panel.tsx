'use client'

import { useState } from 'react'

import { DetailSection, DetailSections } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'

import type { OutsideMember } from '../../types/group.types'
import { AccessTab } from './access-tab'
import { RolesTab } from './roles-tab'

interface TeamAccessPanelProps {
  groupId: string
  canSetAccess: boolean
  canBind: boolean
  canUnbind: boolean
  memberCount?: number
  outsideMembers?: OutsideMember[]
  onShowOutside?: () => void
  onCreateTeam?: () => void
  onChanged?: () => void
}

/**
 * The team's Access tab: one place that answers "what does joining this team
 * give me". What members can do and see (presets and asset scope), then the
 * custom roles added by hand. The outside-member notice is said once: when the
 * presets show it, the roles section keeps only its "give the role to a
 * person" action.
 */
export function TeamAccessPanel({
  groupId,
  canSetAccess,
  canBind,
  canUnbind,
  memberCount,
  outsideMembers,
  onShowOutside,
  onCreateTeam,
  onChanged,
}: TeamAccessPanelProps) {
  const { t } = useTranslation()
  const [noticeAbove, setNoticeAbove] = useState(false)

  return (
    <DetailSections>
      <DetailSection title={t('org.teamSheet.whatMembersGet', 'What members can do and see')}>
        <AccessTab
          groupId={groupId}
          canEdit={canSetAccess}
          memberCount={memberCount}
          outsideMembers={outsideMembers}
          onShowOutside={onShowOutside}
          onCreateTeam={onCreateTeam}
          onChanged={onChanged}
          onOutsideNoticeChange={setNoticeAbove}
        />
      </DetailSection>
      <DetailSection title={t('org.teamSheet.customRoles', 'Custom roles')}>
        <RolesTab
          groupId={groupId}
          canBind={canBind}
          canUnbind={canUnbind}
          memberCount={memberCount}
          outsideMembers={outsideMembers}
          onShowOutside={onShowOutside}
          onCreateTeam={onCreateTeam}
          onChanged={onChanged}
          noticeShownAbove={noticeAbove}
        />
      </DetailSection>
    </DetailSections>
  )
}
