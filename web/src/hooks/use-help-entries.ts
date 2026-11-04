'use client'

import { useMemo } from 'react'
import { Bug, Lightbulb, ShieldAlert, type LucideIcon } from 'lucide-react'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'

export interface HelpEntry {
  id: 'bug' | 'feedback' | 'security'
  label: string
  href: string
  icon: LucideIcon
  /** Extra words the command palette matches. */
  keywords: string[]
  /** The link may be a mailto: (the security contact). */
  allowMailto: boolean
}

/**
 * The report entries of the Help menu and the command palette, in one place so
 * the two stay alike: Report a bug, Send feedback (both hidden when the
 * operator hid them) and Report a security vulnerability, which never goes to
 * a public issue (the security policy, or the operator's own contact).
 */
export function useHelpEntries(): HelpEntry[] {
  const { t } = useTranslation()
  const { help } = useBrand()
  return useMemo(() => {
    const entries: HelpEntry[] = []
    if (!help.hidden) {
      entries.push(
        {
          id: 'bug',
          label: t('help.reportBug', 'Report a bug'),
          href: help.bugUrl,
          icon: Bug,
          keywords: ['issue', 'problem', 'error', 'report'],
          allowMailto: false,
        },
        {
          id: 'feedback',
          label: t('help.sendFeedback', 'Send feedback or request a feature'),
          href: help.feedbackUrl,
          icon: Lightbulb,
          keywords: ['feature', 'idea', 'suggestion', 'feedback'],
          allowMailto: false,
        }
      )
    }
    entries.push({
      id: 'security',
      label: t('help.reportSecurity', 'Report a security vulnerability'),
      href: help.securityUrl,
      icon: ShieldAlert,
      keywords: ['vulnerability', 'security', 'disclosure', 'report'],
      allowMailto: true,
    })
    return entries
  }, [help, t])
}
