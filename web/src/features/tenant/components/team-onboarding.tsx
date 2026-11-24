'use client'

import { EntryHeader } from '@/components/entry'
import { useTranslation } from '@/context/i18n-provider'

import { CreateTeamForm } from './create-team-form'
import { OnboardingFork, type OnboardingOffer } from './onboarding-fork'

interface TeamOnboardingProps {
  /** The user already has teams (came from /select-tenant). */
  hasOtherTeams: boolean
}

/**
 * Body of /onboarding/create-team. A first-time account sees the onboarding
 * fork (invitations, the organization of its verified domain, create one when
 * allowed); an account that already has organizations sees the create form,
 * or, when only administrators create organizations, that notice as the
 * page's title (never a title that offers what the page refuses). The page keeps its
 * sign-out button either way.
 */
export function TeamOnboarding({ hasOtherTeams }: TeamOnboardingProps) {
  const { t } = useTranslation()
  // The title stays in every state, so the page always has its h1, and it
  // names what the page offers once that is known: create, join, or neither
  // (then the title is the notice itself, not an offer the body refuses).
  const header = (offer: OnboardingOffer) => {
    switch (offer) {
      case 'create':
        return hasOtherTeams ? (
          <EntryHeader
            title={t('org.onboarding.createAnother')}
            description={t('org.onboarding.createAnotherDesc')}
          />
        ) : (
          <EntryHeader
            title={t('org.onboarding.createFirst')}
            description={t('org.onboarding.createFirstDesc')}
          />
        )
      case 'join':
        return <EntryHeader title={t('org.onboarding.joinTitle')} />
      case 'none':
        return hasOtherTeams ? (
          <EntryHeader
            title={t('org.onboarding.adminCreatesTitle')}
            description={t('org.onboarding.adminCreatesDesc')}
          />
        ) : (
          <EntryHeader
            title={t('org.onboarding.noOrgTitle')}
            description={t('org.onboarding.noOrgDesc')}
          />
        )
      default:
        return (
          <EntryHeader
            title={
              hasOtherTeams ? t('org.onboarding.anotherTitle') : t('org.onboarding.firstTitle')
            }
          />
        )
    }
  }
  return (
    <OnboardingFork
      variant="plain"
      header={header}
      createSlot={<CreateTeamForm showCancel={false} isFirstTeam={true} />}
      emptySlot={null}
    />
  )
}
