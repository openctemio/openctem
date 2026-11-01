'use client'

import { useCallback, useEffect, useState, useTransition } from 'react'
import Link from '@/components/link'
import {
  Building2,
  ChevronRight,
  KeyRound,
  Loader2,
  Monitor,
  Settings2,
  UserRound,
  type LucideIcon,
} from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import {
  onboardingAcceptAction,
  onboardingOptionsAction,
  type OnboardingOptions,
} from '@/features/auth/actions/local-auth-actions'
import {
  onboardingDeclineAction,
  startAccountSessionAction,
} from '@/features/auth/actions/account-space-actions'
import { ResendVerification } from '@/features/auth/components/resend-verification'
import { CreateTeamForm } from '@/features/tenant/components/create-team-form'
import { ErrorState, PageHeader, PageStack } from '@/features/shared'
import { safeText } from '@/lib/api/error-message'
import { formatRelative } from '@/lib/format-date'

import { useProfile } from '../api'
import { welcomeView } from '../lib/welcome-view'

interface WelcomeHubProps {
  /**
   * The browser holds only a refresh token (or a token of a social sign-in):
   * ask the API for the account-only token first, then load.
   */
  needsSession: boolean
}

const SESSION_RETRY_KEY = 'welcome-organization-retry'

const ACCOUNT_LINKS: Array<{
  href: string
  icon: LucideIcon
  key: string
  fallbackTitle: string
  fallbackDesc: string
}> = [
  {
    href: '/account',
    icon: UserRound,
    key: 'profile',
    fallbackTitle: 'Profile',
    fallbackDesc: 'Your name and contact details',
  },
  {
    href: '/account/security',
    icon: KeyRound,
    key: 'security',
    fallbackTitle: 'Security',
    fallbackDesc: 'Password and two-factor authentication',
  },
  {
    href: '/account/security#sessions',
    icon: Monitor,
    key: 'sessions',
    fallbackTitle: 'Sessions',
    fallbackDesc: 'Devices signed in to your account',
  },
  {
    href: '/account/security#sign-in-methods',
    icon: KeyRound,
    key: 'signInMethods',
    fallbackTitle: 'Sign-in methods',
    fallbackDesc: 'Google, GitHub, Microsoft and your password',
  },
  {
    href: '/account/preferences',
    icon: Settings2,
    key: 'preferences',
    fallbackTitle: 'Preferences',
    fallbackDesc: 'Language, theme and time zone',
  },
]

/**
 * /welcome: the account space of a signed-in person with no organization
 * (api RFC-141). It lists the invitations sent to the person's verified
 * address (accept or decline), offers "Create an organization" only when the
 * API's policy allows it for this person, and links the account pages.
 */
export function WelcomeHub({ needsSession }: WelcomeHubProps) {
  const { t, locale } = useTranslation()
  const { profile } = useProfile()
  const [options, setOptions] = useState<OnboardingOptions | null>(null)
  const [failed, setFailed] = useState(false)
  const [starting, setStarting] = useState(needsSession)
  const [busyRef, setBusyRef] = useState<string | null>(null)
  const [declining, setDeclining] = useState<{ ref: string; name: string } | null>(null)
  const [showCreate, setShowCreate] = useState(false)
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
    if (!needsSession) {
      void load()
      return
    }
    let cancelled = false
    void (async () => {
      const res = await startAccountSessionAction()
      if (cancelled) return
      if (res.success) {
        // The cookies are set: load the page again with the account session.
        window.location.reload()
        return
      }
      if (res.code === 'SESSION') {
        window.location.href = '/login'
        return
      }
      if (res.code === 'HAS_ORGANIZATION') {
        // The person can open an organization: send them to it, once.
        let tried = false
        try {
          tried = sessionStorage.getItem(SESSION_RETRY_KEY) === '1'
          sessionStorage.setItem(SESSION_RETRY_KEY, '1')
        } catch {
          // Storage blocked: treat as tried, show the notice instead of looping.
          tried = true
        }
        if (!tried) {
          window.location.href = '/'
          return
        }
      }
      setStarting(false)
      setFailed(true)
    })()
    return () => {
      cancelled = true
    }
  }, [needsSession, load])

  const view = welcomeView(options)
  const email = profile?.email

  const accept = (ref: string) => {
    setBusyRef(ref)
    startTransition(async () => {
      const res = await onboardingAcceptAction(ref)
      setBusyRef(null)
      if (res.success && res.status === 'joined') {
        toast.success(t('org.onboarding.joined', undefined, { name: res.organizationName }))
        // The organization is selected: reload into it.
        window.location.href = '/'
        return
      }
      if (res.success) {
        toast.success(t('org.onboarding.requested', undefined, { name: res.organizationName }))
      } else if (res.code === 'OFFER_UNAVAILABLE') {
        toast.error(t('org.onboarding.unavailable'))
      } else {
        toast.error(safeText(res.error, t('org.onboarding.failed')))
      }
      void load()
    })
  }

  const decline = () => {
    const target = declining
    if (!target) return
    setDeclining(null)
    setBusyRef(target.ref)
    startTransition(async () => {
      const res = await onboardingDeclineAction(target.ref)
      setBusyRef(null)
      if (res.success) {
        toast.success(t('auth.welcome.declined', undefined, { name: target.name }))
      } else if (res.code === 'OFFER_UNAVAILABLE') {
        toast.error(t('org.onboarding.unavailable'))
      } else {
        toast.error(safeText(res.error, t('org.onboarding.failed')))
      }
      void load()
    })
  }

  const loading = (starting || (!options && !failed)) && !failed

  return (
    <PageStack>
      <PageHeader
        title={t('auth.welcome.title', 'Welcome, {name}', {
          name: profile?.name || email || '',
        })}
        description={t(
          'auth.welcome.subtitle',
          'You are signed in, but you are not in an organization yet.'
        )}
      />

      {loading && (
        <div
          className="flex justify-center py-12"
          role="status"
          aria-label={t('org.onboarding.loading')}
        >
          <Loader2 className="text-muted-foreground size-6 animate-spin" aria-hidden />
        </div>
      )}

      {failed && !options && (
        <ErrorState
          title={t('auth.welcome.loadFailed', 'your invitations')}
          onRetry={() => {
            setFailed(false)
            void load()
          }}
        />
      )}

      {options && view.verifyFirst && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('auth.welcome.verifyTitle', 'Verify your email address')}
            </CardTitle>
            <CardDescription>
              {t('auth.welcome.verifyDesc', 'Verify {email} to see the invitations sent to it.', {
                email: email ?? '',
              })}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ResendVerification email={email} />
          </CardContent>
        </Card>
      )}

      {options && view.invitations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('auth.welcome.invitations', 'Your invitations')}
              <Badge variant="secondary" className="ms-2">
                {view.invitations.length}
              </Badge>
            </CardTitle>
            <CardDescription>
              {t('auth.welcome.invitationsDesc', 'Sent to {email}', { email: email ?? '' })}
            </CardDescription>
          </CardHeader>
          <CardContent className="divide-y">
            {view.invitations.map((inv) => (
              <div
                key={inv.ref}
                className="flex flex-col gap-3 py-3 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <p className="truncate font-medium">{inv.organization_name}</p>
                  <p className="text-muted-foreground text-sm">
                    {inv.invited_by
                      ? t('org.onboarding.invitedBy', undefined, {
                          name: inv.invited_by,
                          role: inv.role,
                        })
                      : t('org.onboarding.invitedAs', undefined, { role: inv.role })}{' '}
                    {t('auth.welcome.expires', 'Expires {when}', {
                      when: formatRelative(inv.expires_at, '', locale),
                    })}
                  </p>
                </div>
                {/* Phone: Join first, full width. Wide: Decline, then Join. */}
                <div className="flex flex-col gap-2 sm:flex-row-reverse">
                  <Button
                    onClick={() => accept(inv.ref)}
                    disabled={busyRef !== null}
                    className="w-full sm:w-auto"
                  >
                    {busyRef === inv.ref && <Loader2 className="size-4 animate-spin" aria-hidden />}
                    {t('org.onboarding.join', 'Join')}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setDeclining({ ref: inv.ref, name: inv.organization_name })}
                    disabled={busyRef !== null}
                    className="w-full sm:w-auto"
                  >
                    {t('auth.welcome.decline', 'Decline')}
                  </Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {options && view.organizations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('org.onboarding.yourCompany')}</CardTitle>
            <CardDescription>{t('org.onboarding.yourCompanyDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="divide-y">
            {view.organizations.map((org) => (
              <div
                key={org.ref}
                className="flex flex-col gap-3 py-3 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex min-w-0 items-center gap-2">
                  <Building2 className="text-muted-foreground size-4 shrink-0" aria-hidden />
                  <div className="min-w-0">
                    <p className="truncate font-medium">{org.organization_name}</p>
                    <p className="text-muted-foreground text-sm">{org.domain}</p>
                  </div>
                </div>
                {org.pending ? (
                  <Badge variant="secondary">{t('org.onboarding.waiting')}</Badge>
                ) : (
                  <Button
                    onClick={() => accept(org.ref)}
                    disabled={busyRef !== null}
                    className="w-full sm:w-auto"
                  >
                    {busyRef === org.ref && <Loader2 className="size-4 animate-spin" aria-hidden />}
                    {org.mode === 'join' ? t('org.onboarding.join') : t('org.onboarding.askToJoin')}
                  </Button>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {options && view.canCreate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              {t('auth.welcome.createTitle', 'Create an organization')}
            </CardTitle>
            <CardDescription>
              {t(
                'auth.welcome.createDesc',
                'An organization is where you manage exposure across a company. You can invite teammates after this.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {showCreate || (view.invitations.length === 0 && view.organizations.length === 0) ? (
              <CreateTeamForm showCancel={false} isFirstTeam={true} />
            ) : (
              <Button variant="outline" onClick={() => setShowCreate(true)}>
                {t('auth.welcome.createCta', 'Create an organization')}
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {options && view.askAdministrator && !view.verifyFirst && (
        <p className="text-muted-foreground text-sm" data-testid="ask-administrator">
          {t(
            'auth.welcome.askAdministrator',
            'Ask your administrator to invite {email}. Invitations sent to this address appear here.',
            { email: email ?? t('auth.welcome.thisAddress', 'this address') }
          )}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('auth.welcome.account', 'Your account')}</CardTitle>
        </CardHeader>
        <CardContent className="divide-y p-0">
          {ACCOUNT_LINKS.map((item) => (
            <Link
              key={item.key}
              href={item.href}
              className="hover:bg-muted/50 focus-visible:ring-ring flex items-center gap-3 px-6 py-3 transition-colors focus-visible:ring-2 focus-visible:outline-none focus-visible:ring-inset"
            >
              <item.icon className="text-muted-foreground size-4 shrink-0" aria-hidden />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">
                  {t(`auth.welcome.link.${item.key}`, item.fallbackTitle)}
                </span>
                <span className="text-muted-foreground block text-sm">
                  {t(`auth.welcome.link.${item.key}Desc`, item.fallbackDesc)}
                </span>
              </span>
              <ChevronRight
                className="text-muted-foreground size-4 shrink-0 rtl:rotate-180"
                aria-hidden
              />
            </Link>
          ))}
        </CardContent>
      </Card>

      <ConfirmDialog
        open={declining !== null}
        onOpenChange={(open) => {
          if (!open) setDeclining(null)
        }}
        title={t('auth.welcome.declineTitle', 'Decline this invitation?')}
        desc={t(
          'auth.welcome.declineDesc',
          '{name} will be told you declined. To join later, ask them to invite you again.',
          { name: declining?.name ?? '' }
        )}
        confirmText={t('auth.welcome.decline', 'Decline')}
        cancelBtnText={t('common.cancel', 'Cancel')}
        destructive
        handleConfirm={decline}
        className="sm:max-w-sm"
      />
    </PageStack>
  )
}
