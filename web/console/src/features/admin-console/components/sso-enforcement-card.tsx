'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { setSSOEnforcement } from '../api/use-admin-organizations'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { AdminOrganization } from '../types'

interface SSOEnforcementCardProps {
  org: AdminOrganization
  canManage: boolean
  onChanged: () => void
}

/**
 * Require members of the organization to sign in with SSO. The API refuses
 * to enable it without a usable SSO path, and the owner can always sign in
 * with a password (break-glass), so this can never lock everyone out.
 */
export function SSOEnforcementCard({ org, canManage, onChanged }: SSOEnforcementCardProps) {
  const { t } = useTranslation()

  const [busy, setBusy] = useState(false)
  const hasSSO = org.saml_enabled || org.active_identity_providers > 0

  const toggle = async (enforced: boolean) => {
    setBusy(true)
    try {
      await setSSOEnforcement(org.id, enforced)
      toast.success(
        enforced
          ? t('admin.ssoEnforcementCard.ssoSignInIsNow', 'SSO sign-in is now required')
          : t(
              'admin.ssoEnforcementCard.passwordSignInIsAllowed',
              'Password sign-in is allowed again'
            )
      )
      onChanged()
    } catch (e) {
      toast.error(
        e instanceof AdminApiError
          ? e.message
          : t(
              'admin.ssoEnforcementCard.couldNotChangeSsoEnforcement',
              'Could not change SSO enforcement'
            )
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {t('admin.ssoEnforcementCard.requireSingleSignOn', 'Require single sign-on')}
        </CardTitle>
        <CardDescription>
          {t(
            'admin.ssoEnforcementCard.membersMustSignInThrough',
            "Members must sign in through the organization's identity provider. The owner can still use a password, so the organization is never locked out."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between gap-4 rounded-md border p-3">
          <div className="text-sm">
            <p className="font-medium">
              {org.sso_enforced
                ? t('admin.ssoEnforcementCard.required', 'Required')
                : t('admin.ssoEnforcementCard.notRequired', 'Not required')}
            </p>
            {!hasSSO && !org.sso_enforced && (
              <p className="text-muted-foreground">
                {t(
                  'admin.ssoEnforcementCard.configureSamlOrAnOidc',
                  'Configure SAML or an OIDC provider first.'
                )}
              </p>
            )}
          </div>
          <Switch
            checked={org.sso_enforced}
            disabled={!canManage || busy || (!hasSSO && !org.sso_enforced)}
            onCheckedChange={(v) => void toggle(v)}
            aria-label={t('admin.ssoEnforcementCard.requireSingleSignOn', 'Require single sign-on')}
          />
        </div>
      </CardContent>
    </Card>
  )
}
