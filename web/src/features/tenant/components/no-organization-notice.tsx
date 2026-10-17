'use client'

import { Building2 } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'
import { EmptyState } from '@/features/shared/components/empty-state'

interface NoOrganizationNoticeProps {
  /**
   * The user already belongs to other organizations (they came from team
   * selection or the dashboard): say only that they cannot create one here.
   */
  hasOtherTeams?: boolean
  className?: string
}

/**
 * Shown instead of the create-team form when the installation lets only the
 * platform administrator create organizations (`the admin_only sign-up policy`).
 */
export function NoOrganizationNotice({
  hasOtherTeams = false,
  className,
}: NoOrganizationNoticeProps) {
  const { t } = useTranslation()
  return (
    <EmptyState
      icon={Building2}
      className={className}
      title={hasOtherTeams ? t('org.onboarding.adminCreatesTitle') : t('org.onboarding.noOrgTitle')}
      description={
        hasOtherTeams ? t('org.onboarding.adminCreatesDesc') : t('org.onboarding.noOrgDesc')
      }
    />
  )
}
