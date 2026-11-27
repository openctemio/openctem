'use client'

import { useCallback } from 'react'

import { useTranslation } from '@/context/i18n-provider'

/**
 * Plain words for the access tokens a key or connection carries
 * ("findings:read"). A token we do not know shows a generic word, never the
 * raw value.
 */
export function usePermissionLabel() {
  const { t } = useTranslation()

  return useCallback(
    (token: string): string => {
      switch (token) {
        case 'assets:read':
          return t('settings.perm.assetsRead', 'Read assets')
        case 'assets:write':
          return t('settings.perm.assetsWrite', 'Change assets')
        case 'findings:read':
          return t('settings.perm.findingsRead', 'Read findings')
        case 'findings:write':
          return t('settings.perm.findingsWrite', 'Change findings')
        case 'scans:read':
          return t('settings.perm.scansRead', 'Read scans')
        case 'scans:write':
          return t('settings.perm.scansWrite', 'Change scans')
        case 'integrations:read':
          return t('settings.perm.integrationsRead', 'Read integrations')
        case 'compliance:frameworks:read':
          return t('settings.perm.complianceRead', 'Read compliance frameworks')
        case 'pentest:campaigns:read':
          return t('settings.perm.pentestCampaignsRead', 'Read pentest campaigns')
        case 'pentest:findings:read':
          return t('settings.perm.pentestFindingsRead', 'Read pentest findings')
        case 'pentest:retests:read':
          return t('settings.perm.pentestRetestsRead', 'Read pentest retests')
        case 'pentest:templates:read':
          return t('settings.perm.pentestTemplatesRead', 'Read pentest templates')
        default:
          return t('settings.perm.other', 'Other access')
      }
    },
    [t]
  )
}
