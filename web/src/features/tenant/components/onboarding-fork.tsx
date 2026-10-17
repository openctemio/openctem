'use client'

import { useCallback, useEffect, useState, useTransition } from 'react'
import { Building2, Clock, Loader2, Mail } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import {
  onboardingAcceptAction,
  onboardingOptionsAction,
  type OnboardingOptions,
} from '@/features/auth/actions/local-auth-actions'

interface OnboardingForkProps {
  /** The create-organization form, shown when the account may create one. */
  createSlot: React.ReactNode
  /** Shown when nothing at all is offered. */
  emptySlot: React.ReactNode
}

/**
 * The onboarding fork of an account without an organization (api RFC-104):
 * pending invitations first, then the organization that claims the verified
 * email domain (join, or ask to join), then "create an organization". Every
 * offer is taken by its opaque reference; the server checks it again.
 */
export function OnboardingFork({ createSlot, emptySlot }: OnboardingForkProps) {
  const { t } = useTranslation()
  const [options, setOptions] = useState<OnboardingOptions | null>(null)
  const [failed, setFailed] = useState(false)
  const [busyRef, setBusyRef] = useState<string | null>(null)
  const [, startTransition] = useTransition()

  const load = useCallback(async () => {
    const res = await onboardingOptionsAction()
    if (res.success) {
      setOptions(res.options)
      setFailed(false)
    } else if (res.sessionExpired) {
      window.location.href = '/login'
    } else {
      setFailed(true)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const take = (ref: string) => {
    setBusyRef(ref)
    startTransition(async () => {
      const res = await onboardingAcceptAction(ref)
      setBusyRef(null)
      if (res.success && res.status === 'joined') {
        toast.success(t('org.onboarding.joined', undefined, { name: res.organizationName }))
        // Fresh tenant cookies: reload into the organization.
        window.location.href = '/'
        return
      }
      if (res.success) {
        toast.success(t('org.onboarding.requested', undefined, { name: res.organizationName }))
      } else if (res.code === 'OFFER_UNAVAILABLE') {
        toast.error(t('org.onboarding.unavailable'))
      } else {
        toast.error(res.error || t('org.onboarding.failed'))
      }
      void load()
    })
  }

  if (!options && !failed) {
    return (
      <div
        className="flex justify-center py-16"
        role="status"
        aria-label={t('org.onboarding.loading')}
      >
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  const invitations = options?.invitations ?? []
  const organizations = options?.organizations ?? []
  const canCreate = options?.can_create_organization ?? false
  const nothing = invitations.length === 0 && organizations.length === 0 && !canCreate

  return (
    <div className="space-y-6">
      {options && !options.email_verified && (
        <p className="rounded-md border p-3 text-sm text-muted-foreground">
          {t('org.onboarding.verifyFirst')}
        </p>
      )}

      {invitations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('org.onboarding.invitations')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {invitations.map((inv) => (
              <div key={inv.ref} className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2">
                  <Mail className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0">
                    <p className="truncate font-medium">{inv.organization_name}</p>
                    <p className="text-xs text-muted-foreground">
                      {inv.invited_by
                        ? t('org.onboarding.invitedBy', undefined, {
                            name: inv.invited_by,
                            role: inv.role,
                          })
                        : t('org.onboarding.invitedAs', undefined, { role: inv.role })}
                    </p>
                  </div>
                </div>
                <Button size="sm" onClick={() => take(inv.ref)} disabled={busyRef !== null}>
                  {busyRef === inv.ref && <Loader2 className="me-1.5 h-4 w-4 animate-spin" />}
                  {t('org.onboarding.accept')}
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {organizations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('org.onboarding.yourCompany')}</CardTitle>
            <CardDescription>{t('org.onboarding.yourCompanyDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {organizations.map((org) => (
              <div key={org.ref} className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2">
                  <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-0">
                    <p className="truncate font-medium">{org.organization_name}</p>
                    <p className="text-xs text-muted-foreground">{org.domain}</p>
                  </div>
                </div>
                {org.pending ? (
                  <Badge variant="secondary" className="gap-1">
                    <Clock className="h-3 w-3" />
                    {t('org.onboarding.waiting')}
                  </Badge>
                ) : (
                  <Button size="sm" onClick={() => take(org.ref)} disabled={busyRef !== null}>
                    {busyRef === org.ref && <Loader2 className="me-1.5 h-4 w-4 animate-spin" />}
                    {org.mode === 'join' ? t('org.onboarding.join') : t('org.onboarding.askToJoin')}
                  </Button>
                )}
              </div>
            ))}
            {organizations.some((o) => o.pending) && (
              <p className="text-xs text-muted-foreground">{t('org.onboarding.waitingHint')}</p>
            )}
          </CardContent>
        </Card>
      )}

      {canCreate && (
        <div className="space-y-3">
          {(invitations.length > 0 || organizations.length > 0) && (
            <p className="text-center text-sm text-muted-foreground">
              {t('org.onboarding.orCreate')}
            </p>
          )}
          {createSlot}
        </div>
      )}

      {(nothing || failed) && emptySlot}
    </div>
  )
}
