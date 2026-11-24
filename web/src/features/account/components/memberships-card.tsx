'use client'

import { useState, useTransition } from 'react'
import Link from '@/components/link'
import { Building2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EntryActions } from '@/components/entry'
import { SettingsSection } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { localLogoutAction, selectTenantAction } from '@/features/auth/actions/local-auth-actions'
import { blockedReasonText } from '@/features/organization/lib/external-access'
import type { TenantMembership } from '@/lib/api/user-tenant-types'
import { safeText } from '@/lib/api/error-message'
import { navigateAfterSessionChange } from '@/lib/session-navigation'

import { membershipStep, type MembershipRefusal } from '../lib/membership-step'

/** One organization or invitation: name and details, its actions at the end (under it on a phone). */
export const HUB_ROW =
  'flex flex-wrap items-center justify-between gap-x-4 gap-y-3 border-t border-border-subtle py-3.5 [&>:first-child]:min-w-0 [&>:first-child]:flex-[1_1_13rem]'

/**
 * The account's own memberships, each with its one next step. Opening one goes
 * through the organization's token exchange, so every rule of that
 * organization (two-factor, its own single sign-on, suspension) is checked by
 * the API there; this list only says what to do when it refuses. It shows the
 * person's own rows only: name, role and state, nothing of the organization.
 */
export function MembershipsCard({
  memberships,
  currentId,
}: {
  memberships: TenantMembership[]
  /** The organization open in this browser, if any. */
  currentId: string | null
}) {
  const { t } = useTranslation()
  const [busyId, setBusyId] = useState<string | null>(null)
  const [refusals, setRefusals] = useState<Record<string, MembershipRefusal>>({})
  const [, startTransition] = useTransition()

  const open = (m: TenantMembership) => {
    if (m.id === currentId) {
      navigateAfterSessionChange('/')
      return
    }
    setBusyId(m.id)
    startTransition(async () => {
      const res = await selectTenantAction(m.id)
      setBusyId(null)
      if (res.success) {
        navigateAfterSessionChange('/', { replace: true })
        return
      }
      const step = membershipStep(res.code)
      if (step) {
        setRefusals((prev) => ({ ...prev, [m.id]: step }))
        return
      }
      if (res.code === 'SESSION_EXPIRED') {
        window.location.replace('/login')
        return
      }
      toast.error(
        safeText(res.error, t('account.orgs.openFailed', 'Could not open {name}', { name: m.name }))
      )
    })
  }

  return (
    <SettingsSection
      framed
      id="memberships"
      title={t('account.orgs.membershipsTitle', 'Your organizations')}
      description={t(
        'account.orgs.membershipsDesc',
        'Open one to work in it. Each organization checks its own sign-in rules when you open it.'
      )}
    >
      <ul data-testid="account-memberships">
        {memberships.map((m) => {
          const refusal = refusals[m.id]
          const blocked = !!m.blocked_reason
          return (
            <li key={m.id} className={HUB_ROW}>
              <div className="flex min-w-0 items-center gap-3">
                <span className="bg-surface-sunken flex size-8 shrink-0 items-center justify-center rounded-sm">
                  <Building2 className="size-4" aria-hidden />
                </span>
                <div className="min-w-0">
                  <p className="text-body flex items-center gap-2 font-medium">
                    <span className="truncate">{m.name}</span>
                    {m.id === currentId && (
                      <Badge variant="secondary">{t('account.orgs.current', 'Open now')}</Badge>
                    )}
                  </p>
                  <p className="text-cap text-muted-foreground">
                    {t(`org.role.${m.role}`, m.role)}
                  </p>
                  {blocked && (
                    <p className="text-cap text-muted-foreground" data-testid="membership-blocked">
                      {t(
                        `account.orgs.blocked.${m.blocked_reason}`,
                        blockedReasonText(m.blocked_reason)
                      )}
                    </p>
                  )}
                  {refusal && (
                    <p className="text-cap text-muted-foreground" role="status">
                      {refusal === 'two_factor_setup' &&
                        t(
                          'account.orgs.needsTwoFactor',
                          'This organization requires two-factor authentication. Set it up, then open the organization again.'
                        )}
                      {refusal === 'two_factor_sign_in' &&
                        t(
                          'account.orgs.needsTwoFactorSignIn',
                          'This organization requires a sign-in with your authenticator code. Sign in again to open it.'
                        )}
                      {refusal === 'single_sign_on' &&
                        t(
                          'account.orgs.needsSso',
                          'This organization signs you in through its own single sign-on.'
                        )}
                    </p>
                  )}
                </div>
              </div>
              {!blocked && (
                <EntryActions layout="row">
                  {refusal === 'two_factor_setup' && (
                    <Button asChild>
                      <Link href="/account/security#two-factor">
                        {t('account.orgs.setUpTwoFactor', 'Set up two-factor')}
                      </Link>
                    </Button>
                  )}
                  {refusal === 'two_factor_sign_in' && (
                    <Button onClick={() => void localLogoutAction('/login')}>
                      {t('account.orgs.signInAgain', 'Sign in again')}
                    </Button>
                  )}
                  {refusal === 'single_sign_on' && (
                    <Button
                      onClick={() =>
                        void localLogoutAction(`/login?org=${encodeURIComponent(m.slug)}`)
                      }
                    >
                      {t('account.orgs.signInSso', 'Sign in with single sign-on')}
                    </Button>
                  )}
                  <Button
                    variant={refusal ? 'outline' : 'default'}
                    onClick={() => open(m)}
                    disabled={busyId !== null}
                  >
                    {busyId === m.id && <Loader2 className="size-4 animate-spin" aria-hidden />}
                    {t('account.orgs.open', 'Open')}
                  </Button>
                </EntryActions>
              )}
            </li>
          )
        })}
      </ul>
    </SettingsSection>
  )
}
