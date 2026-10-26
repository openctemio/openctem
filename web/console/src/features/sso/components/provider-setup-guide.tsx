'use client'

import { CopyableUrl } from './copyable-url'
import { useTranslation } from '@/context/i18n-provider'
import type { SSOProviderType } from '@/features/sso/types/sso.types'

/** The sign-in return address to register at the identity provider. */
export function ssoRedirectUri(appUrl: string, provider: SSOProviderType): string {
  return `${appUrl}/auth/sso/callback/${provider}`
}

/** The address the identity provider calls when a person signs out or is disabled. */
export function ssoBackchannelLogoutUrl(appUrl: string): string {
  return `${appUrl}/api/v1/auth/backchannel-logout`
}

/**
 * What to enter at the identity provider before filling in the form below:
 * the redirect URI (every provider) and, for Microsoft Entra ID, the logout
 * URL and the optional claims the sign-in depends on.
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
          {isEntra && (
            <CopyableUrl
              label={t(
                'admin.ssoSetupGuide.logoutUrl',
                'Front-channel logout URL (enables sign-out of OpenCTEM sessions)'
              )}
              url={ssoBackchannelLogoutUrl(appUrl)}
            />
          )}
          <p className="text-muted-foreground text-xs">
            {t(
              'admin.ssoSetupGuide.addressHint',
              'These use the address in APP_URL. If the API is published on a different address, use that address for the logout URL.'
            )}
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
            <li>
              <code>sid</code>{' '}
              {t(
                'admin.ssoSetupGuide.claimSid',
                '(signs out one OpenCTEM session; without it a sign-out ends all of the user sessions).'
              )}
            </li>
          </ul>
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
