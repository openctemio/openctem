import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { env } from '@/lib/env'
import { validateRedirectUrl } from '@/lib/redirect'
import { hasSessionCookie } from '@/lib/middleware/auth'

// Use refactored LoginForm from features directory
import { LoginForm } from '@/features/auth/components/login-form'
import { SignUpPrompt } from '@/features/auth/components/sign-up-prompt'
import { LegalNotice } from '@/features/auth/components/legal-notice'
import { isInvitationReturnTo } from '@/features/auth/lib/self-register'

interface LoginPageProps {
  searchParams: Promise<{
    // The page to return to: `next` from the proxy (src/proxy.ts), `redirect`
    // from the client after a session ends, `returnTo` from invitations.
    next?: string
    redirect?: string
    returnTo?: string
    org?: string
    error?: string
    // Preserved from the invitation flow — when a user clicks an
    // invite link and doesn't have an account, the invitation page
    // redirects to /login?email=alice@co.com&returnTo=/invitations.
    // The login page passes this email (and the invitation returnTo)
    // through to the "Sign up" link so the register form can pre-fill it
    // and send the invitation token.
    email?: string
  }>
}

export default async function SignIn({ searchParams }: LoginPageProps) {
  const params = await searchParams
  const returnTo = params.returnTo || params.next || params.redirect
  const redirectTo = validateRedirectUrl(returnTo, '/')

  // Already signed in? The same check as the proxy (cookie present and shaped
  // like a token): if the two disagreed, a cookie the proxy rejects but this
  // page accepts would bounce the browser between them.
  const cookieStore = await cookies()
  if (hasSessionCookie((name) => cookieStore.get(name)?.value)) {
    // User is authenticated - determine where to redirect
    const hasTenant = cookieStore.get(env.cookies.tenant)?.value
    const hasPendingTenants = cookieStore.get(env.cookies.pendingTenants)?.value

    if (hasTenant) {
      // User has selected a team - redirect to dashboard or specified URL
      redirect(redirectTo)
    } else if (hasPendingTenants) {
      // User has multiple teams but hasn't selected one - redirect to select-tenant
      redirect('/select-tenant')
    } else if (isInvitationReturnTo(redirectTo)) {
      // Special case: invitation links — let them through with current auth
      // so the invitation acceptance flow can issue a fresh tenant cookie.
      redirect(redirectTo)
    }

    // WARNING: Dangling auth state: refresh_token exists but no tenant cookie and
    // no pendingTenants cookie. This typically happens when the user logged
    // in with a multi-tenant account, walked away from /select-tenant, and
    // the pendingTenants cookie expired before they picked a team.
    //
    // We CANNOT assume "no tenants" here — the user almost certainly has
    // tenants on the server, we just lost the cached list locally. The
    // previous behaviour (redirect to /onboarding/create-team) caused the
    // user to create a duplicate tenant they didn't want.
    //
    // Instead: fall through and render the login form. The user re-enters
    // credentials, /auth/login returns the tenant list fresh, and the
    // normal flow resumes. The dangling refresh_token is harmless — the
    // successful re-login will overwrite it.
  }

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="text-lg tracking-tight">Sign in</CardTitle>
        <CardDescription>
          Enter your email and password below to <br />
          log into your account.
          {/* Sign-up is offered only when the server allows it, or when the
              visitor came from an invitation (accounts are otherwise created
              by an administrator). */}
          <SignUpPrompt returnTo={returnTo} email={params.email} />
        </CardDescription>
      </CardHeader>
      <CardContent>
        <LoginForm redirectTo={redirectTo} orgSlug={params.org} />
      </CardContent>
      <CardFooter className="justify-center empty:hidden">
        <LegalNotice action="clicking sign in" />
      </CardFooter>
    </Card>
  )
}
