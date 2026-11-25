'use client'

import { useEffect, useState, useTransition, type ReactNode } from 'react'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import { Clock, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import {
  EntryActions,
  EntryBackLink,
  EntryBanner,
  EntryCard,
  EntryHeader,
  EntryLinkProblem,
  EntryLine,
  EntryNote,
} from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { TEXT_LINK_CLASS } from '@/components/ui/text-link'
import { ToneChip } from '@/components/ui/tone-chip'
import { csrfFetch } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import {
  INVITATION_PAGE,
  clearInvitationToken,
  takeInvitationToken,
} from '@/features/auth/lib/invitation-token'
import { registerHref } from '@/features/auth/lib/self-register'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { OrgAvatar } from '@/components/layout/org-avatar'
import { authErrorText } from '@/features/auth/lib/auth-error-codes'
import { MfaSessionStep } from '@/features/auth/components/mfa-session-step'
import { localLogoutAction, selectTenantAction } from '@/features/auth/actions/local-auth-actions'
import { navigateAfterSessionChange } from '@/lib/session-navigation'
import { parseRetryAfter } from '@/lib/api/rate-limit-backoff'
import { useTranslation } from '@/context/i18n-provider'
import {
  InvitationGrantsNotice,
  type InvitationGrants,
} from '@/features/organization/components/invitation-grants'
import {
  type InvitationNextStep,
  invitationNextStep,
  invitationNextStepHref,
} from './invitation-next-step'

interface InvitationData {
  invitation: InvitationGrants & {
    id: string
    email: string
    role: string
    pending: boolean
    expires_at: string
    invited_by?: string
    inviter_name?: string
  }
  tenant: {
    id: string
    name: string
    slug: string
  }
}

interface InvitationViewProps {
  /**
   * Whether the visitor has a session (auth or refresh cookie). Without one,
   * Accept/Decline cannot work, so the page offers "Sign in" and "Create your
   * account" instead — the latter works even with open registration disabled,
   * because the invitation token admits the invited email.
   */
  hasSession: boolean
}

/** POSTs the invitation token in the body (never in the URL). */
function postToken(url: string, token: string): Promise<Response> {
  return csrfFetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
}

/** A refused decline: its message is already the console's own text. */
class DeclineRefused extends Error {}

/** The words for a refused request, from the API's code; never the server's sentence. */
async function errorMessage(
  response: Response,
  fallback: string,
  t: Parameters<typeof authErrorText>[1]
): Promise<string> {
  const data = (await response.json().catch(() => ({}))) as { code?: string }
  return authErrorText(data.code, t, fallback)
}

/** The API refused a token only because the organization requires 2FA. */
async function isMfaEnrollmentRequired(response: Response): Promise<boolean> {
  if (response.status !== 403) return false
  const data = (await response
    .clone()
    .json()
    .catch(() => ({}))) as { code?: string }
  return data.code === 'MFA_ENROLLMENT_REQUIRED'
}

export function InvitationView({ hasSession }: InvitationViewProps) {
  const router = useRouter()
  const { t } = useTranslation()
  const [confirmDecline, setConfirmDecline] = useState(false)
  const [declined, setDeclined] = useState(false)

  const [isPending, startTransition] = useTransition()
  const [isLoading, setIsLoading] = useState(true)
  const [token, setToken] = useState<string | null>(null)
  const [invitation, setInvitation] = useState<InvitationData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [acceptError, setAcceptError] = useState<string | null>(null)
  // The invitation is accepted but the organization needs a second factor:
  // the page walks the person through it instead of showing an error.
  const [joinedNeedsMfa, setJoinedNeedsMfa] = useState(false)
  // Accepted here, but the organization could not be opened yet: the page
  // shows the accepted card with "Open <organization>".
  const [joined, setJoined] = useState(false)
  const [openError, setOpenError] = useState<string | null>(null)
  // Refused for a reason only another sign-in fixes: the page shows that one
  // step instead of Accept or Open (which would be refused again).
  const [nextStep, setNextStep] = useState<InvitationNextStep | null>(null)
  // Opening was refused for now (too many requests, a server failure, no
  // answer): seconds left before "Open" is offered again, from the server's
  // Retry-After.
  const [openWait, setOpenWait] = useState(0)

  useEffect(() => {
    if (openWait <= 0) return
    const timer = setTimeout(() => setOpenWait((s) => s - 1), 1000)
    return () => clearTimeout(timer)
  }, [openWait])

  // The token never goes back into a URL: sign-in and sign-up return to the
  // bare invitation page, which finds the token kept for this tab.
  const invitationPath = INVITATION_PAGE
  const invitationLoginHref = `/login?returnTo=${encodeURIComponent(invitationPath)}&email=${encodeURIComponent(invitation?.invitation.email || '')}`

  // Take the token from the link's fragment (or this tab), then look it up.
  useEffect(() => {
    const found = takeInvitationToken()
    if (!found) {
      setError(t('org.acceptInvite.incomplete'))
      setIsLoading(false)
      return
    }
    setToken(found)

    async function fetchInvitation(tok: string) {
      try {
        const response = await postToken(endpoints.invitations.lookup(), tok)
        if (!response.ok) {
          if (response.status === 404) {
            clearInvitationToken()
            setError(t('org.acceptInvite.notFound'))
          } else {
            setError(await errorMessage(response, t('org.acceptInvite.loadFailed'), t))
          }
          return
        }
        setInvitation(await response.json())
      } catch {
        setError(t('org.acceptInvite.loadFailed'))
      } finally {
        setIsLoading(false)
      }
    }

    fetchInvitation(found)
    // Runs once per page load; t only changes with the locale.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Lands in the organization: a full page load, so every part of the
  // console reads the session the selection just set (a client-side push
  // kept the previous organization, or none).
  function landInOrganization(name: string) {
    clearInvitationToken()
    navigateAfterSessionChange('/', {
      replace: true,
      flash: { kind: 'success', title: t('org.acceptInvite.joinedOrg', undefined, { org: name }) },
    })
  }

  /**
   * Makes the invited organization the session's active one. Accepting only
   * adds the membership: the session still names the previous organization
   * (or none, for an account without one), so `/` would open that instead.
   * The API checks the membership on the exchange; the id is never trusted
   * on its own.
   */
  async function openInvitedOrganization(data: InvitationData): Promise<void> {
    const selected = await selectTenantAction(data.tenant.id)
    if (selected.success) {
      landInOrganization(data.tenant.name)
      return
    }
    if (selected.code === 'MFA_ENROLLMENT_REQUIRED') {
      // Joined; the organization requires two-factor authentication.
      setJoinedNeedsMfa(true)
      return
    }
    const step = invitationNextStep(selected.code)
    if (step) {
      setNextStep(step)
      return
    }
    if (selected.code === 'SESSION_EXPIRED') {
      // The membership exists: signing in again opens it.
      navigateAfterSessionChange('/login', { replace: true })
      return
    }
    setJoined(true)
    if (selected.status === 0 || selected.status === 429 || (selected.status ?? 0) >= 500) {
      // Nothing was decided about the membership: say why and when to retry.
      const seconds = Math.max(1, Math.ceil(parseRetryAfter(selected.retryAfter) / 1000))
      setOpenWait(seconds)
      setOpenError(
        t(
          selected.status === 429
            ? 'org.acceptInvite.openBusy'
            : 'org.acceptInvite.openUnavailable',
          undefined,
          { org: data.tenant.name, seconds }
        )
      )
      return
    }
    setOpenError(t('org.acceptInvite.openFailed', undefined, { org: data.tenant.name }))
  }

  function handleOpenOrganization() {
    if (!invitation) return
    setOpenError(null)
    setOpenWait(0)
    startTransition(async () => {
      try {
        await openInvitedOrganization(invitation)
      } catch {
        // The action itself did not answer: the same wait as no answer from the API.
        setOpenWait(parseRetryAfter(null) / 1000)
        setOpenError(
          t('org.acceptInvite.openUnavailable', undefined, {
            org: invitation.tenant.name,
            seconds: parseRetryAfter(null) / 1000,
          })
        )
      }
    })
  }

  /**
   * A refused accept. When the invitation was accepted meanwhile (in another
   * tab, or by an earlier click), the page shows it as accepted with
   * "Open <organization>" instead of an error.
   */
  async function acceptRefused(response: Response, tok: string) {
    const data = (await response.json().catch(() => ({}))) as { code?: string }
    const step = invitationNextStep(data.code)
    if (step) {
      setNextStep(step)
      return
    }
    const message = authErrorText(data.code, t, t('org.acceptInvite.acceptFailed'))
    const fresh = await postToken(endpoints.invitations.lookup(), tok)
      .then((r) => (r.ok ? (r.json() as Promise<InvitationData>) : null))
      .catch(() => null)
    if (fresh && !fresh.invitation.pending) {
      clearInvitationToken()
      setInvitation(fresh)
      return
    }
    setAcceptError(message)
    toast.error(message)
  }

  // Accept invitation - tries access token first, then refresh token
  function handleAccept() {
    if (!token) return
    setAcceptError(null)
    startTransition(async () => {
      try {
        // First try with access token (for users with tenant)
        const response = await postToken(endpoints.invitations.accept(), token)

        if (response.ok) {
          clearInvitationToken()
          if (invitation) await openInvitedOrganization(invitation)
          return
        }

        // If 401, try with refresh token (for users without tenant)
        if (response.status === 401) {
          const refreshResponse = await postToken(endpoints.invitations.acceptWithRefresh(), token)

          if (refreshResponse.ok) {
            clearInvitationToken()
            if (invitation) await openInvitedOrganization(invitation)
            return
          }

          if (refreshResponse.status === 401) {
            // No valid session - send the visitor to sign in, then back here
            router.push(invitationLoginHref)
            return
          }

          if (await isMfaEnrollmentRequired(refreshResponse)) {
            // Joined; the organization requires two-factor authentication.
            // Not an error: set it up here, then open the organization.
            setJoinedNeedsMfa(true)
            return
          }

          await acceptRefused(refreshResponse, token)
          return
        }

        await acceptRefused(response, token)
      } catch {
        const message = t('org.acceptInvite.acceptFailed')
        setAcceptError(message)
        toast.error(message)
      }
    })
  }

  // Decline the invitation. The decline endpoint needs only the token, so it
  // works signed out too; the page then says so instead of redirecting.
  function handleDecline() {
    if (!token) return
    startTransition(async () => {
      try {
        const response = await postToken(endpoints.invitations.decline(), token)
        if (!response.ok) {
          throw new DeclineRefused(
            await errorMessage(response, t('org.acceptInvite.declineFailed'), t)
          )
        }
        clearInvitationToken()
        setDeclined(true)
        toast.success(t('org.acceptInvite.declinedToast'))
      } catch (err) {
        toast.error(
          err instanceof DeclineRefused ? err.message : t('org.acceptInvite.declineFailed')
        )
      } finally {
        setConfirmDecline(false)
      }
    })
  }

  // Calculate days until expiry
  function getDaysUntilExpiry(): number {
    if (!invitation) return 0
    const expiryDate = new Date(invitation.invitation.expires_at)
    const now = new Date()
    const diffTime = expiryDate.getTime() - now.getTime()
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  }

  // Loading state
  if (isLoading) {
    return (
      <EntryCard aria-busy="true">
        <Skeleton className="h-8 w-2/3" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-9 w-full" />
      </EntryCard>
    )
  }

  // Error state
  if (error) {
    return (
      <EntryLinkProblem
        title={t('org.acceptInvite.linkProblemTitle', 'This invitation link does not work')}
        description={error}
        exit={hasSession ? 'app' : 'signIn'}
      />
    )
  }

  // Declined here: say so (the visitor may have no session to go anywhere).
  if (declined && invitation) {
    return (
      <EntryCard>
        <EntryHeader
          title={t('org.acceptInvite.declinedTitle')}
          description={t('org.acceptInvite.declinedBody', undefined, {
            org: invitation.tenant.name,
          })}
        />
        <EntryActions>
          <EntryBackLink to={hasSession ? 'app' : 'signIn'} />
        </EntryActions>
      </EntryCard>
    )
  }

  // Joined, but the organization requires two-factor authentication: set it up
  // here (the same step the sign-in page uses), then open the organization.
  if (joinedNeedsMfa && invitation) {
    return (
      <EntryCard>
        <EntryHeader
          title={t('org.acceptInvite.joinedMfaTitle', undefined, { org: invitation.tenant.name })}
          description={t('org.acceptInvite.joinedMfaBody')}
        />
        <MfaSessionStep
          tenantId={invitation.tenant.id}
          onComplete={() => landInOrganization(invitation.tenant.name)}
          onSessionExpired={() => router.push(invitationLoginHref)}
          onReauthRequired={() =>
            router.push(
              `/login?reason=mfa_required&returnTo=${encodeURIComponent(invitationPath)}&email=${encodeURIComponent(invitation.invitation.email || '')}`
            )
          }
        />
      </EntryCard>
    )
  }

  // Refused for a reason only another sign-in fixes: that one step.
  if (nextStep && invitation) {
    const org = invitation.tenant.name
    const email = invitation.invitation.email
    const vars = { org, email }
    const text: Record<InvitationNextStep, { title: string; body: string; action: string }> = {
      identity_provider: {
        title: t('org.acceptInvite.nextIdpTitle', undefined, vars),
        body: t('org.acceptInvite.nextIdpBody', undefined, vars),
        action: t('org.acceptInvite.nextIdpAction', undefined, vars),
      },
      identity_provider_mfa: {
        title: t('org.acceptInvite.nextIdpTitle', undefined, vars),
        body: t('org.acceptInvite.nextIdpMfaBody', undefined, vars),
        action: t('org.acceptInvite.nextIdpAction', undefined, vars),
      },
      own_sign_in: {
        title: t('org.acceptInvite.nextOwnTitle', undefined, vars),
        body: t('org.acceptInvite.nextOwnBody', undefined, vars),
        action: t('org.acceptInvite.nextOwnAction', undefined, vars),
      },
      other_address: {
        title: t('org.acceptInvite.nextOtherTitle', undefined, vars),
        body: t('org.acceptInvite.nextOtherBody', undefined, vars),
        action: t('org.acceptInvite.nextOtherAction', undefined, vars),
      },
    }
    const href = invitationNextStepHref(nextStep, {
      slug: invitation.tenant.slug,
      email,
      invitationPath,
    })
    // This session cannot do it: sign it out, then continue at the step.
    const continueAtStep = () =>
      startTransition(async () => {
        await localLogoutAction(href).catch(() => {
          window.location.href = href
        })
      })
    return (
      <EntryCard data-testid="invitation-next-step">
        <EntryHeader title={text[nextStep].title} description={text[nextStep].body} />
        <EntryActions>
          <Button variant="signal" onClick={continueAtStep} disabled={isPending}>
            {isPending && <Loader2 aria-hidden className="size-4 animate-spin" />}
            {text[nextStep].action}
          </Button>
        </EntryActions>
      </EntryCard>
    )
  }

  // Invitation expired or already accepted (here, or earlier)
  if (invitation && (joined || !invitation.invitation.pending)) {
    const isExpired = !joined && new Date(invitation.invitation.expires_at) < new Date()
    // A signed-in person who accepted can open the organization from here
    // (the API refuses the selection to anyone who is not a member).
    const canOpen = hasSession && !isExpired

    return (
      <EntryCard>
        <EntryHeader
          title={
            isExpired ? t('org.acceptInvite.expiredTitle') : t('org.acceptInvite.acceptedTitle')
          }
          description={
            isExpired ? t('org.acceptInvite.expiredBody') : t('org.acceptInvite.acceptedBody')
          }
        />
        <OrganizationRow name={invitation.tenant.name} />

        {openError && <EntryBanner tone="danger">{openError}</EntryBanner>}

        <EntryActions>
          {canOpen ? (
            <Button
              variant="signal"
              onClick={handleOpenOrganization}
              disabled={isPending || openWait > 0}
            >
              {isPending && <Loader2 aria-hidden className="size-4 animate-spin" />}
              {openWait > 0
                ? t('org.acceptInvite.openRetryIn', undefined, { seconds: openWait })
                : t('org.acceptInvite.openOrg', undefined, { org: invitation.tenant.name })}
            </Button>
          ) : null}
          {/* One way out: the organization (signed in), else back to sign in. */}
          <EntryBackLink to={hasSession ? 'app' : 'signIn'} />
        </EntryActions>
      </EntryCard>
    )
  }

  const daysUntilExpiry = getDaysUntilExpiry()
  const orgName = invitation?.tenant.name ?? ''
  // The API names the inviter (display name only, never an email); an
  // unnamed account falls back to a neutral label.
  const inviterName =
    invitation?.invitation.inviter_name?.trim() || t('org.acceptInvite.aTeamMember')

  return (
    <>
      <EntryCard>
        <EntryHeader
          title={t('org.acceptInvite.title')}
          description={t('org.acceptInvite.subtitle', undefined, {
            name: inviterName,
            org: orgName,
          })}
        />

        {/* The organization, the address invited and how long the invitation
            stays open. The inviter is named in the line above. */}
        <OrganizationRow
          name={orgName}
          invitee={
            invitation?.invitation.email
              ? t('org.acceptInvite.forEmail', undefined, { email: invitation.invitation.email })
              : undefined
          }
          expiry={
            daysUntilExpiry <= 3 && daysUntilExpiry > 0 ? (
              <ToneChip
                tone="caution"
                icon={Clock}
                label={
                  daysUntilExpiry === 1
                    ? t('org.acceptInvite.expiresInOne')
                    : t('org.acceptInvite.expiresInDays', undefined, { days: daysUntilExpiry })
                }
              />
            ) : null
          }
        />

        {/* What accepting gives */}
        {invitation && (
          <InvitationGrantsNotice grants={invitation.invitation} organization={orgName} />
        )}

        {acceptError && (
          <EntryBanner tone="danger" title={t('org.acceptInvite.cannotAccept')}>
            <p>{acceptError}</p>
          </EntryBanner>
        )}

        <EntryActions>
          {/* No session: sign in, or create the account for the invited email. */}
          {!hasSession && invitation && (
            <>
              <Button asChild variant="signal">
                <Link href={invitationLoginHref}>{t('org.acceptInvite.signInToAccept')}</Link>
              </Button>
              <Button asChild variant="outline">
                <Link
                  href={registerHref({
                    returnTo: invitationPath,
                    email: invitation.invitation.email,
                  })}
                >
                  {t('org.acceptInvite.createAccount')}
                </Link>
              </Button>
            </>
          )}

          {hasSession && (
            <Button variant="signal" onClick={handleAccept} disabled={isPending}>
              {isPending && <Loader2 aria-hidden className="size-4 animate-spin" />}
              {t('org.acceptInvite.accept')}
            </Button>
          )}

          {/* Decline: always offered; it needs only the invitation. */}
          {invitation && (
            <Button variant="outline" onClick={() => setConfirmDecline(true)} disabled={isPending}>
              {t('org.acceptInvite.decline')}
            </Button>
          )}
        </EntryActions>

        {!hasSession && invitation && (
          <EntryNote className="text-center">
            {t('org.acceptInvite.newHere', undefined, { email: invitation.invitation.email })}
          </EntryNote>
        )}

        {/* Switch account */}
        {hasSession && (
          <EntryLine className="text-muted-foreground">
            {t('org.acceptInvite.notYou', undefined, {
              email: invitation?.invitation.email ?? '',
            })}{' '}
            <button
              type="button"
              className={TEXT_LINK_CLASS.inline}
              onClick={() => router.push(invitationLoginHref)}
            >
              {t('org.acceptInvite.otherAccount')}
            </button>
          </EntryLine>
        )}
      </EntryCard>

      <ConfirmDialog
        open={confirmDecline}
        onOpenChange={setConfirmDecline}
        title={t('org.acceptInvite.declineTitle')}
        desc={t('org.acceptInvite.declineBody', undefined, { org: orgName })}
        confirmText={t('org.acceptInvite.decline')}
        destructive
        isLoading={isPending}
        handleConfirm={handleDecline}
      />
    </>
  )
}

/**
 * The invited organization: its avatar (the switcher's), its name, the
 * address the invitation is for and an optional expiry chip.
 */
function OrganizationRow({
  name,
  invitee,
  expiry,
}: {
  name: string
  invitee?: string
  expiry?: ReactNode
}) {
  return (
    <div className="border-border flex items-center gap-3 rounded-lg border p-3">
      <OrgAvatar name={name} />
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <p className="text-body truncate font-medium">{name}</p>
        {invitee && (
          <p className="text-cap text-muted-foreground [overflow-wrap:anywhere]">{invitee}</p>
        )}
        {expiry}
      </div>
    </div>
  )
}
