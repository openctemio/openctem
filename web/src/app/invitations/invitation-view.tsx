'use client'

import { useEffect, useState, useTransition } from 'react'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import { Building2, Check, Loader2, X, LogIn, Clock, AlertTriangle, UserPlus } from 'lucide-react'
import { toast } from 'sonner'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { csrfFetch } from '@/lib/api/client'
import { endpoints } from '@/lib/api/endpoints'
import {
  INVITATION_PAGE,
  clearInvitationToken,
  takeInvitationToken,
} from '@/features/auth/lib/invitation-token'
import { registerHref } from '@/features/auth/lib/self-register'

interface InvitationData {
  invitation: {
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

async function errorMessage(response: Response, fallback: string): Promise<string> {
  const data = (await response.json().catch(() => ({}))) as { message?: string }
  return data.message || fallback
}

export function InvitationView({ hasSession }: InvitationViewProps) {
  const router = useRouter()

  const [isPending, startTransition] = useTransition()
  const [isLoading, setIsLoading] = useState(true)
  const [token, setToken] = useState<string | null>(null)
  const [invitation, setInvitation] = useState<InvitationData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [acceptError, setAcceptError] = useState<string | null>(null)

  // The token never goes back into a URL: sign-in and sign-up return to the
  // bare invitation page, which finds the token kept for this tab.
  const invitationPath = INVITATION_PAGE
  const invitationLoginHref = `/login?returnTo=${encodeURIComponent(invitationPath)}&email=${encodeURIComponent(invitation?.invitation.email || '')}`

  // Take the token from the link's fragment (or this tab), then look it up.
  useEffect(() => {
    const found = takeInvitationToken()
    if (!found) {
      setError(
        'This invitation link is incomplete. Open the link from your invitation email again.'
      )
      setIsLoading(false)
      return
    }
    setToken(found)

    async function fetchInvitation(t: string) {
      try {
        const response = await postToken(endpoints.invitations.lookup(), t)
        if (!response.ok) {
          if (response.status === 404) {
            clearInvitationToken()
            setError('Invitation not found or has expired')
          } else {
            setError(await errorMessage(response, 'Failed to load invitation'))
          }
          return
        }
        setInvitation(await response.json())
      } catch {
        setError('Failed to load invitation. Please try again.')
      } finally {
        setIsLoading(false)
      }
    }

    fetchInvitation(found)
  }, [])

  // Accepting sets fresh auth/tenant cookies: navigate client-side, then refresh
  // so server components and the session are re-read with them.
  function navigateWithFreshSession(path: string) {
    clearInvitationToken()
    router.push(path)
    router.refresh()
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
          toast.success('You have joined the team!')
          navigateWithFreshSession('/dashboard')
          return
        }

        // If 401, try with refresh token (for users without tenant)
        if (response.status === 401) {
          const refreshResponse = await postToken(endpoints.invitations.acceptWithRefresh(), token)

          if (refreshResponse.ok) {
            toast.success('You have joined the team!')
            navigateWithFreshSession('/dashboard')
            return
          }

          if (refreshResponse.status === 401) {
            // No valid session - send the visitor to sign in, then back here
            router.push(invitationLoginHref)
            return
          }

          const errorMsg = await errorMessage(refreshResponse, 'Failed to accept invitation')
          setAcceptError(errorMsg)
          toast.error(errorMsg)
          return
        }

        const errorMsg = await errorMessage(response, 'Failed to accept invitation')
        setAcceptError(errorMsg)
        toast.error(errorMsg)
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to accept invitation'
        setAcceptError(message)
        toast.error(message)
      }
    })
  }

  // Decline invitation
  function handleDecline() {
    if (!token) return
    startTransition(async () => {
      try {
        const response = await postToken(endpoints.invitations.decline(), token)
        if (!response.ok) {
          throw new Error(await errorMessage(response, 'Failed to decline invitation'))
        }
        clearInvitationToken()
        toast.success('Invitation declined')
        router.push('/')
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to decline invitation'
        toast.error(message)
        // Still redirect to home even if decline fails
        router.push('/')
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
      <div className="min-h-screen flex items-center justify-center p-4 bg-muted/30">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <Skeleton className="h-8 w-48 mx-auto mb-2" />
            <Skeleton className="h-4 w-64 mx-auto" />
          </CardHeader>
          <CardContent className="space-y-4">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-10 w-full" />
          </CardContent>
        </Card>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-muted/30">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
              <AlertTriangle className="h-6 w-6 text-destructive" />
            </div>
            <CardTitle className="text-xl">Invitation Error</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
            <div className="flex flex-col gap-2">
              <Button variant="outline" className="w-full" onClick={() => router.push('/login')}>
                <LogIn className="me-2 h-4 w-4" />
                Go to Login
              </Button>
              <Button variant="ghost" className="w-full" onClick={() => router.push('/')}>
                Go to Home
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Invitation expired or already accepted
  if (invitation && !invitation.invitation.pending) {
    const isExpired = new Date(invitation.invitation.expires_at) < new Date()
    const statusText = isExpired ? 'Expired' : 'Already Accepted'
    const StatusIcon = isExpired ? Clock : Check

    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-muted/30">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div
              className={`mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full ${isExpired ? 'bg-warning/10' : 'bg-success/10'}`}
            >
              <StatusIcon className={`h-6 w-6 ${isExpired ? 'text-warning' : 'text-success'}`} />
            </div>
            <CardTitle className="text-xl">Invitation {statusText}</CardTitle>
            <CardDescription>
              {isExpired
                ? 'This invitation has expired. Please contact the team admin for a new invitation.'
                : 'This invitation has already been accepted.'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Team Info */}
            <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50">
              <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10 text-primary">
                <Building2 className="h-5 w-5" />
              </div>
              <div>
                <p className="font-medium">{invitation.tenant.name}</p>
                <p className="text-sm text-muted-foreground capitalize">
                  {invitation.invitation.role}
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <Button className="w-full" onClick={() => router.push('/login')}>
                <LogIn className="me-2 h-4 w-4" />
                Go to Login
              </Button>
              <Button variant="ghost" className="w-full" onClick={() => router.push('/')}>
                Go to Home
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  const daysUntilExpiry = getDaysUntilExpiry()

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-muted/30">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center pb-2">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
            <Building2 className="h-7 w-7 text-primary" />
          </div>
          <CardTitle className="text-xl">Team Invitation</CardTitle>
          <CardDescription>You&apos;ve been invited to join a team</CardDescription>
        </CardHeader>

        <CardContent className="space-y-5">
          {/* Team Info Card */}
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-start gap-4">
              <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-primary text-primary-foreground font-bold text-lg">
                {invitation?.tenant.name.charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-lg truncate">{invitation?.tenant.name}</p>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="secondary" className="capitalize">
                    {invitation?.invitation.role}
                  </Badge>
                  {daysUntilExpiry <= 3 && daysUntilExpiry > 0 && (
                    <Badge variant="outline" className="text-warning border-warning/50">
                      <Clock className="h-3 w-3 me-1" />
                      Expires in {daysUntilExpiry} day{daysUntilExpiry > 1 ? 's' : ''}
                    </Badge>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Invitation Details */}
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between py-2 border-b">
              <span className="text-muted-foreground">Invited by</span>
              <span className="font-medium">
                {/* The API names the inviter (display name only, never an
                    email); an unnamed account falls back to a neutral label. */}
                {invitation?.invitation.inviter_name?.trim() || 'A team member'}
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-muted-foreground">Invitation for</span>
              <span className="font-medium">{invitation?.invitation.email}</span>
            </div>
          </div>

          {/* Accept Error */}
          {acceptError && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Cannot accept invitation</AlertTitle>
              <AlertDescription>{acceptError}</AlertDescription>
            </Alert>
          )}

          {/* No session: sign in, or create the account for the invited email. */}
          {!hasSession && invitation && (
            <div className="flex flex-col gap-2">
              <Button asChild className="w-full" size="lg">
                <Link href={invitationLoginHref}>
                  <LogIn className="me-2 h-4 w-4" />
                  Sign in to accept
                </Link>
              </Button>
              <Button asChild variant="outline" className="w-full">
                <Link
                  href={registerHref({
                    returnTo: invitationPath,
                    email: invitation.invitation.email,
                  })}
                >
                  <UserPlus className="me-2 h-4 w-4" />
                  Create your account
                </Link>
              </Button>
              <p className="text-center text-xs text-muted-foreground">
                New here? Create an account for <strong>{invitation.invitation.email}</strong>, then
                accept the invitation.
              </p>
            </div>
          )}

          {/* Action Buttons */}
          {hasSession && (
            <div className="flex flex-col gap-2">
              <Button className="w-full" size="lg" onClick={handleAccept} disabled={isPending}>
                {isPending ? (
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                ) : (
                  <Check className="me-2 h-4 w-4" />
                )}
                Accept Invitation
              </Button>

              <Button
                variant="outline"
                className="w-full"
                onClick={handleDecline}
                disabled={isPending}
              >
                <X className="me-2 h-4 w-4" />
                Decline
              </Button>
            </div>
          )}

          {/* Switch account link */}
          {hasSession && (
            <p className="text-xs text-center text-muted-foreground">
              Not <strong>{invitation?.invitation.email}</strong>?{' '}
              <button
                type="button"
                className="text-primary hover:underline"
                onClick={() => router.push(invitationLoginHref)}
              >
                Log in with different account
              </button>
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
