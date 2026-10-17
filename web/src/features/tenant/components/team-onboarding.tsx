'use client'

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
  const create = (
    <>
      <div className="mb-8 text-center">
        <h1 className="text-2xl font-semibold tracking-tight">
          {hasOtherTeams ? t('org.onboarding.createAnother') : t('org.onboarding.createFirst')}
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {hasOtherTeams
            ? t('org.onboarding.createAnotherDesc')
            : t('org.onboarding.createFirstDesc')}
        </p>
      </div>
      <CreateTeamForm showCancel={false} isFirstTeam={true} />
    </>
  )
  return (
    <OnboardingFork
      createSlot={create}
      emptySlot={<NoOrganizationNotice hasOtherTeams={hasOtherTeams} />}
    />
  )
}
