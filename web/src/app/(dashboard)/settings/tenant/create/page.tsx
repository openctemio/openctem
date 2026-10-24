'use client'

/**
 * Create Team Page
 *
 * Page for creating a new team/tenant. When only the platform administrator
 * creates organizations (the admin_only sign-up policy), it says so instead
 * of showing a form the server would refuse.
 */

import { Loader2 } from 'lucide-react'

import { Main } from '@/components/layout'
import { useCanCreateOrganization } from '@/features/auth/hooks/use-can-create-organization'
import { PageHeader, PageStack } from '@/features/shared'
import { CreateTeamForm, NoOrganizationNotice } from '@/features/tenant'
import { useTranslation } from '@/context/i18n-provider'

export default function CreateTeamPage() {
  const { t } = useTranslation()
  const { canCreate, isLoading } = useCanCreateOrganization()

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader title={t('settings.createTeam.title', 'Create team')} />

          <div className="flex justify-center">
            {isLoading ? (
              <Loader2
                className="h-6 w-6 animate-spin text-muted-foreground"
                aria-label="Loading"
              />
            ) : canCreate ? (
              <CreateTeamForm />
            ) : (
              <NoOrganizationNotice hasOtherTeams className="w-full max-w-lg" />
            )}
          </div>
        </PageStack>
      </Main>
    </>
  )
}
