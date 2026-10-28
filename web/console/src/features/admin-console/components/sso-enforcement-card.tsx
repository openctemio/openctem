'use client'

import { useTranslation } from '@/context/i18n-provider'
import { useState } from 'react'
import { toast } from 'sonner'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { setSSOEnforcement, useSSOEnforcement } from '../api/use-admin-organizations'
import { AdminApiError } from '@console/lib/admin-api/client'
import type { AdminOrganization } from '../types'

interface SSOEnforcementCardProps {
  org: AdminOrganization
  canManage: boolean
  onChanged: () => void
}

/**
 * Require members of the organization to sign in with SSO. The API refuses
 * to enable it without a usable SSO path, an owner or admin who has signed in
 * through the identity provider, and an owner with two-factor authentication
 * (owner break-glass is a password and that second factor), so this can never
 * lock everyone out. Turning it on revokes the user API keys and connector
 * grants that exist at that moment unless the box is unticked.
 */
export function SSOEnforcementCard({ org, canManage, onChanged }: SSOEnforcementCardProps) {
  const { t } = useTranslation()

  const [busy, setBusy] = useState(false)
  const [confirmOff, setConfirmOff] = useState(false)
  const [revoke, setRevoke] = useState(true)
  const hasSSO = org.saml_enabled || org.active_identity_providers > 0
  const { data: state, mutate: refreshState } = useSSOEnforcement(org.id)
  const readiness = state?.readiness
  // Unknown until the API answers: the switch stays off, and the API checks again.
  const ready = !!readiness && readiness.admin_sso_signin && readiness.owner_second_factor
  const credentialCount = readiness ? readiness.api_keys + readiness.connector_grants : 0

  const toggle = async (enforced: boolean) => {
    setBusy(true)
    try {
      if (enforced) await setSSOEnforcement(org.id, true, revoke)
      else await setSSOEnforcement(org.id, false)
      void refreshState()
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
      setConfirmOff(false)
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
            "Members must sign in through the organization's identity provider. An owner can still get in with a password and their second factor, and that is recorded."
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
            {!org.sso_enforced && readiness && (
              <ul className="my-2 space-y-1">
                <li>
                  {readiness.admin_sso_signin
                    ? t(
                        'admin.ssoEnforcementCard.adminSignInDone',
                        'An owner or admin has signed in through the identity provider.'
                      )
                    : t(
                        'admin.ssoEnforcementCard.adminSignInMissing',
                        'Waiting for an owner or admin to sign in through the identity provider once.'
                      )}
                </li>
                <li>
                  {readiness.owner_second_factor
                    ? t(
                        'admin.ssoEnforcementCard.ownerFactorDone',
                        'An owner has two-factor authentication, so owner break-glass works.'
                      )
                    : t(
                        'admin.ssoEnforcementCard.ownerFactorMissing',
                        'Waiting for an owner to turn on two-factor authentication.'
                      )}
                </li>
              </ul>
            )}
            {!org.sso_enforced && (
              <p className="text-muted-foreground">
                {t(
                  'admin.ssoEnforcementCard.needsVerifiedDomain',
                  'Needs at least one domain verified for SSO. If a domain later fails its DNS check, SSO stays required and the owners are alerted.'
                )}
              </p>
            )}
          </div>
          <Switch
            checked={org.sso_enforced}
            disabled={!canManage || busy || (!org.sso_enforced && (!hasSSO || !ready))}
            onCheckedChange={(v) => {
              // Turning enforcement off weakens sign-in, so it asks first; turning it on is one click.
              if (v) void toggle(true)
              else setConfirmOff(true)
            }}
            aria-label={t('admin.ssoEnforcementCard.requireSingleSignOn', 'Require single sign-on')}
          />
        </div>
        {!org.sso_enforced && readiness && credentialCount > 0 && (
          <div className="mt-3 flex items-start gap-2 text-sm">
            <Checkbox
              id={`revoke-${org.id}`}
              checked={revoke}
              onCheckedChange={(v) => setRevoke(v === true)}
              disabled={!canManage || busy}
            />
            <Label htmlFor={`revoke-${org.id}`} className="font-normal leading-snug">
              {t(
                'admin.ssoEnforcementCard.revokeCredentials',
                'Revoke the {keys} API keys and {grants} AI connections that exist now. Keys and connections made later from an SSO sign-in keep working.',
                { keys: readiness.api_keys, grants: readiness.connector_grants }
              )}
            </Label>
          </div>
        )}
      </CardContent>
      <ConfirmDialog
        open={confirmOff}
        onOpenChange={(open) => !busy && setConfirmOff(open)}
        destructive
        title={t('admin.ssoEnforcementCard.offTitle', 'Allow password sign-in for {name}?', {
          name: org.name,
        })}
        desc={t(
          'admin.ssoEnforcementCard.offDesc',
          'Members can sign in with a password again and no longer have to use the identity provider. The SSO configuration is kept, and you can require SSO again at any time.'
        )}
        confirmText={t('admin.ssoEnforcementCard.offButton', 'Allow password sign-in')}
        isLoading={busy}
        handleConfirm={() => toggle(false)}
      />
    </Card>
  )
}
