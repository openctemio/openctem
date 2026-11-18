'use client'

import { EntryHeader } from '@/components/entry'
import { useTranslation } from '@/context/i18n-provider'

import { CreateTeamForm } from './create-team-form'
import { NoOrganizationNotice } from './no-organization-notice'
import { OnboardingFork } from './onboarding-fork'

interface TeamOnboardingProps {
  /** The user already has teams (came from /select-tenant). */
  hasOtherTeams: boolean
}

/**
 * Body of /onboarding/create-team. A first-time account sees the onboarding
 * fork (invitations, the organization of its verified domain, create one when
 * allowed); an account that already has teams sees the create form, or the
 * notice when only administrators create organizations. The page keeps its
 * sign-out button either way.
 */
export function TeamOnboarding({ hasOtherTeams }: TeamOnboardingProps) {
  const { t } = useTranslation()
  // The title stays while the offers load and in every outcome, so the page
  // always has its h1; the form is one of the things under it.
  return (
    <>
      <EntryHeader
        title={hasOtherTeams ? t('org.onboarding.createAnother') : t('org.onboarding.createFirst')}
        description={
          hasOtherTeams
            ? t('org.onboarding.createAnotherDesc')
            : t('org.onboarding.createFirstDesc')
        }
      />
      <OnboardingFork
        variant="plain"
        createSlot={<CreateTeamForm showCancel={false} isFirstTeam={true} />}
        emptySlot={<NoOrganizationNotice hasOtherTeams={hasOtherTeams} />}
      />
    </>
  )
}
