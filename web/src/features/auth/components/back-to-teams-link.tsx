'use client'

import Link from '@/components/link'
import { ArrowLeft } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

/**
 * "Back to team selection" link for the create-team page.
 *
 * Only shown when the user arrived at /onboarding/create-team from the
 * select-tenant flow (i.e., they already have other teams to go back to).
 */
export function BackToTeamsLink() {
  const { t } = useTranslation()
  return (
    <Button variant="outline" asChild>
      <Link href="/select-tenant">
        <ArrowLeft aria-hidden className="size-4" />
        {t('auth.onboarding.backToTeams', 'Back to team selection')}
      </Link>
    </Button>
  )
}
