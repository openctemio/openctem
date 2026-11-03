'use client'

import { CopyableUrl } from './copyable-url'
import { useTranslation } from '@/context/i18n-provider'
import type { SSOProviderType } from '@/features/sso/types/sso.types'

/** The sign-in return address to register at the identity provider. */
export function ssoRedirectUri(appUrl: string, provider: SSOProviderType): string {
  return `${appUrl}/auth/sso/callback/${provider}`
}

/**
 * What to enter at the identity provider before filling in the form below:
 * the redirect URI (every provider) and, for Microsoft Entra ID, the optional
 * claims the sign-in depends on. Entra ID sends no back-channel logout, so no
 * logout address is offered: ending access when a person leaves goes through
 * SCIM deprovisioning.
 */
export function ProviderSetupGuide({
  provider,
  appUrl,
}: {
  provider: SSOProviderType
  appUrl: string | undefined
}) {
  const { t } = useTranslation()
  const isEntra = provider === 'entra_id'
  return (
    <div className="bg-muted/40 space-y-3 rounded-lg border p-3" data-testid="sso-setup-guide">
      <p className="text-sm font-medium">
        {isEntra
          ? t('admin.ssoSetupGuide.titleEntra', 'Set up in Microsoft Entra ID')
          : t('admin.ssoSetupGuide.title', 'Set up at the identity provider')}
      </p>
      {appUrl ? (
        <div className="space-y-3">
          <CopyableUrl
            label={t('admin.ssoSetupGuide.redirectUri', 'Redirect URI (type: Web)')}
            url={ssoRedirectUri(appUrl, provider)}
          />
          <p className="text-muted-foreground text-xs">
            {t('admin.ssoSetupGuide.redirectHint', 'This uses the address in APP_URL.')}
          </p>
        </div>
      ) : (
        <p className="text-muted-foreground text-xs">
          {t(
            'admin.ssoSetupGuide.noAppUrl',
            'The public address of the app is not set. Set APP_URL on the API to see the addresses to register.'
          )}
        </p>
      )}
      {isEntra && (
        <div className="space-y-1">
          <p className="text-xs font-medium">
            {t(
              'admin.ssoSetupGuide.claimsTitle',
              'Token configuration: add these optional ID token claims'
            )}
          </p>
          <ul className="text-muted-foreground list-disc space-y-0.5 ps-5 text-xs">
            <li>
              <code>xms_edov</code>{' '}
              {t(
                'admin.ssoSetupGuide.claimEdov',
                '(required) proves the email address is verified; sign-in is refused without it.'
              )}
            </li>
            <li>
              <code>auth_time</code>{' '}
              {t('admin.ssoSetupGuide.claimAuthTime', '(needed for step-up re-authentication).')}
            </li>
          </ul>
          <p className="text-muted-foreground text-xs">
            {t(
              'admin.ssoSetupGuide.entraRevocation',
              'Disabling or deleting a user in Entra ID does not end their {product} sessions. Turn on SCIM provisioning to remove access as soon as a person is removed in Entra ID.'
            )}
          </p>
          <p className="text-muted-foreground text-xs">
            {t(
              'admin.ssoSetupGuide.secretExpiry',
              'Client secrets expire. Note the expiry date and replace the secret here before it passes.'
            )}
          </p>
        </div>
      )}
    </div>
  )
}
