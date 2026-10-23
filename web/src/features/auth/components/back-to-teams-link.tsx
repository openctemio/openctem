'use client'

import Link from '@/components/link'
import { ArrowLeft } from 'lucide-react'

import { useTranslation } from '@/context/i18n-provider'

/** Link from the create-team page back to the team list. */
export function BackToTeamsLink() {
  const { t } = useTranslation()
  return (
    <Link
      href="/select-tenant"
      className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
    >
      <ArrowLeft className="h-3.5 w-3.5" />
      {t('auth.onboarding.backToTeams', 'Back to team selection')}
    </Link>
  )
}
