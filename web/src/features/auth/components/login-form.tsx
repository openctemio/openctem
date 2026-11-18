/**
 * Login Form Component
 *
 * Handles user authentication with support for:
 * - Local auth (email/password) via backend API
 * - Social auth (Google, GitHub, Microsoft) via OAuth2
 */

'use client'

import { useEffect, useId, useState, useTransition } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useRouter, useSearchParams } from 'next/navigation'
import { KeyRound, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { navigateAfterSessionChange } from '@/lib/session-navigation'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { EntryBanner, EntryDivider } from '@/components/entry'
import { TextLink } from '@/components/ui/text-link'
import { PasswordInput } from '@/components/password-input'
import { SocialProviderButtons } from './social-provider-buttons'

import { isHttpsUrl, validateRedirectUrl } from '@/lib/redirect'
import { authErrorText } from '@/features/auth/lib/auth-error-codes'
import { loginErrorMessage } from '@/features/auth/lib/login-error'
import { ResendVerification } from './resend-verification'
import { isInvitationReturnTo } from '@/features/auth/lib/self-register'
import { useTranslation } from '@/context/i18n-provider'

// Import schema and server actions
import { loginSchema, type LoginInput } from '../schemas/auth.schema'
import { sessionEndedMessage } from '../lib/session-ended'
import { translatingResolver } from '../lib/translating-resolver'
import {
  loginAction,
  selectTenantAction,
  type LoginResult,
  type LoginTenant,
  type MfaPurpose,
} from '../actions/local-auth-actions'
import { PendingDeletionDialog } from './pending-deletion-dialog'
import { MfaStep } from './mfa-step'
import { initiateSocialLogin, type SocialProvider } from '../actions/social-auth-actions'

// SSO imports
import { useAuthProviders } from '../api/use-auth-providers'
import { TurnstileWidget } from './turnstile-widget'
import { useTenantSSOProviders } from '@/features/sso/api/use-sso-api'
import { useEmailDiscovery } from '../hooks/use-email-discovery'
import { initiateSSOLogin } from '@/features/sso/actions/sso-auth-actions'
import { type SSOProviderType } from '@/features/sso/types/sso.types'
import { identityProviderLabel } from '@/lib/identity-provider-label'

// ============================================
// TYPES
// ============================================

interface LoginFormProps extends React.HTMLAttributes<HTMLFormElement> {
  /**
   * URL to redirect to after successful login
   * @default '/'
   */
  redirectTo?: string

  /**
   * Whether to show social login buttons (Google, GitHub, Microsoft)
   * @default true
   */
  showSocialLogin?: boolean

  /**
   * Organization slug for SSO login (?org= parameter)
   * When set, fetches and displays tenant-specific SSO providers
   */
  orgSlug?: string

  /**
   * Step-up for an SSO account (?reauth=1): the identity provider is asked to
   * authenticate the user again instead of reusing its session.
   */
  reauth?: boolean
}

/**
 * Full page navigation after login, so the cookies set by the Server Action
 * are picked up (router.push would keep the old auth state). A message is
 * shown on the page that loads.
 */
function hardNavigate(url: string, signedIn?: string) {
  navigateAfterSessionChange(
    url,
    signedIn ? { flash: { kind: 'success', title: signedIn } } : undefined
  )
}

// ============================================
// COMPONENT
// ============================================

export function LoginForm({
  className,
  redirectTo = '/',
  showSocialLogin = true,
  orgSlug,
  reauth = false,
  ...props
}: LoginFormProps) {
  const [isPending, startTransition] = useTransition()
  const [loadingProvider, setLoadingProvider] = useState<SocialProvider | null>(null)
  const [loadingSSOProvider, setLoadingSSOProvider] = useState<SSOProviderType | null>(null)
  // Set when the password was right but a second factor is needed.
  const [mfaPurpose, setMfaPurpose] = useState<MfaPurpose | null>(null)
  const [mfaOrgs, setMfaOrgs] = useState<string[] | undefined>(undefined)
  // An owner of an organization scheduled for deletion is offered to cancel
  // before the sign-in goes on.
  const [pendingDeletion, setPendingDeletion] = useState<{
    result: LoginResult
    organizations: LoginTenant[]
  } | null>(null)
  // After repeated failed sign-ins from this address the API asks for the
  // security check (CAPTCHA_REQUIRED); it is then shown and sent along.
  const [captchaRequired, setCaptchaRequired] = useState(false)
  const [captchaToken, setCaptchaToken] = useState('')
  const [captchaReset, setCaptchaReset] = useState(0)
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null)
  // Why the last attempt failed. It stays in the card above the form (not a
  // toast that fades) until the next attempt starts; the text is the same one
  // the page has always shown for that refusal.
  const [failure, setFailure] = useState<string | null>(null)
  // The callback error and the session-ended reason describe how the visitor
  // arrived; they give way once the visitor tries again.
  const [attempted, setAttempted] = useState(false)
  const noticeId = useId()
  const router = useRouter()
  const searchParams = useSearchParams()

  // Validate redirectTo to prevent open redirect attacks
  const safeRedirectTo = validateRedirectUrl(redirectTo, '/')

  // Fetch which social providers the backend actually has configured, so we
  // only render buttons that will work (no 404 dead-affordances). While it
  // loads, the block keeps its place (SocialProviderButtons).
  const { data: authProviders, error: authProvidersError } = useAuthProviders()

  // Check for error from OAuth/SSO callback
  // Only a known code's message is shown, never the raw parameter: a crafted
  // link must not put arbitrary text on the sign-in page.
  const errorParam = searchParams.get('error')
  // A social sign-in to a linked password account comes back here for its
  // second factor (the challenge is in an httpOnly cookie).
  const mfaParam = searchParams.get('mfa')
  useEffect(() => {
    if (mfaParam === 'verify' || mfaParam === 'enroll') setMfaPurpose(mfaParam)
  }, [mfaParam])
  const { t } = useTranslation()
  const loginError = errorParam ? loginErrorMessage(errorParam) : null
  const errorMessage = loginError ? t(loginError.key, loginError.fallback) : null
  // A social sign-in found an account that signs in another way: the notice
  // stays on the page with what to do, instead of a toast that fades.
  const accountExists = errorParam === 'account_exists'
  // A social sign-in hit an identity the organization's single sign-on manages.
  const useOrgSso = errorParam === 'use_org_sso'
  const callbackError = errorMessage && !accountExists && !useOrgSso ? errorMessage : null

  // Sent when a session ended because an organization requires two-factor
  // authentication and the session could not set it up. Only the known value
  // shows a message.
  const reasonParam = searchParams.get('reason')
  const mfaRequiredReason = reasonParam === 'mfa_required'
  // A session the platform ended (reuse, expiry, signed out elsewhere) says
  // why instead of silently showing the form.
  const sessionEnded = sessionEndedMessage(reasonParam)
  const reasonNotice = mfaRequiredReason
    ? t(
        'auth.login.mfaRequiredReason',
        'An organization you belong to requires two-factor authentication. Sign in to set it up.'
      )
    : sessionEnded
      ? t(sessionEnded.key, sessionEnded.fallback)
      : null

  // One notice at a time: the last attempt's failure, else how the visitor
  // arrived (a failed callback, then a session the platform ended).
  const notice: { text: string; tone: 'danger' | 'info' } | null = failure
    ? { text: failure, tone: 'danger' }
    : attempted
      ? null
      : callbackError
        ? { text: callbackError, tone: 'danger' }
        : reasonNotice
          ? { text: reasonNotice, tone: 'info' }
          : null

  /** A new attempt starts: the previous answer leaves the card. */
  function startAttempt() {
    setAttempted(true)
    setFailure(null)
  }

  // Form setup with centralized schema
  const form = useForm<LoginInput>({
    resolver: translatingResolver(zodResolver(loginSchema), t),
    defaultValues: {
      email: '',
      password: '',
    },
  })

  // Email-first sign-in: when the typed email's domain signs in through an
  // organization's SSO, offer that organization's SSO like ?org= does.
  const typedEmail = form.watch('email') ?? ''
  const discoveredOrg = useEmailDiscovery(typedEmail, !orgSlug)
  const ssoOrg = orgSlug ?? discoveredOrg ?? undefined

  // Fetch the organization's SSO providers (?org= or discovered)
  const { data: ssoProviders } = useTenantSSOProviders(ssoOrg ?? null)

  /**
   * Handle form submission for local auth
   */
  function onSubmit(data: LoginInput) {
    startAttempt()
    startTransition(async () => {
      const result = await loginAction({
        email: data.email,
        password: data.password,
        captchaToken: captchaRequired ? captchaToken : undefined,
      })
      if (captchaRequired) setCaptchaReset((n) => n + 1)

      if (result.success && result.mfaRequired && result.mfaPurpose) {
        form.resetField('password')
        setMfaOrgs(result.mfaOrgs)
        setMfaPurpose(result.mfaPurpose)
        return
      }

      handleLoginResult(result)
    })
  }

  /**
   * Route a finished login (password only, or after the second factor).
   */
  function handleLoginResult(result: LoginResult) {
    if (result.pendingDeletion && result.pendingDeletion.length > 0) {
      setPendingDeletion({ result, organizations: result.pendingDeletion })
      return
    }
    if (result.success) {
      // Store user data in sessionStorage for sidebar display
      if (result.user) {
        try {
          sessionStorage.setItem(
            'app_user',
            JSON.stringify({
              id: result.user.id,
              name: result.user.name,
              email: result.user.email,
            })
          )
        } catch {
          // Ignore sessionStorage errors
        }
      }

      // Case 1: Multiple tenants - redirect to tenant selection
      if (result.requiresTenantSelection) {
        toast.success(t('auth.login.selectTeam', 'Please select a team to continue'))
        router.push('/select-tenant')
        return
      }

      // Case 2: No tenants - check if user has a specific destination (e.g., invitation)
      if (result.tenants && result.tenants.length === 0) {
        // If returnTo is an invitation page, go there first (user can accept and get a tenant)
        if (isInvitationReturnTo(safeRedirectTo)) {
          hardNavigate(safeRedirectTo, t('auth.login.success', 'Signed in'))
          return
        }
        // Otherwise the account space: invitations, the account pages, and
        // creating an organization where the installation allows it. The page
        // decides, so this toast stays neutral.
        hardNavigate('/welcome', t('auth.login.success', 'Signed in'))
        return
      }

      // Case 3: Single tenant - proceed to dashboard
      // A full page navigation (hardNavigate), so the cookies set by the
      // Server Action are picked up properly.
      hardNavigate(safeRedirectTo, t('auth.login.success', 'Signed in'))
    } else if (result.code === 'ORGANIZATION_SUSPENDED') {
      setFailure(
        t('auth.organizationSuspended.message', 'This organization is suspended. Contact support.')
      )
    } else if (result.code === 'EMAIL_NOT_VERIFIED') {
      // The password was right but the address is not verified: say so and
      // offer to send the link again.
      setUnverifiedEmail(form.getValues('email'))
      setFailure(t('auth.login.emailNotVerified', 'Your email address is not verified yet.'))
    } else if (result.code === 'CAPTCHA_REQUIRED') {
      setCaptchaRequired(true)
      setFailure(t('auth.login.captchaRequired'))
    } else {
      setFailure(authErrorText(result.code, t, t('auth.login.failed', 'Sign-in failed')))
    }
  }

  /**
   * Handle social login (Google, GitHub, Microsoft)
   */
  async function handleSocialLogin(provider: SocialProvider) {
    startAttempt()
    setLoadingProvider(provider)
    try {
      const res = await initiateSocialLogin(provider, safeRedirectTo)
      if (!res.ok || !isHttpsUrl(res.url)) throw new Error('start_failed')
      // Keep the loading state: the page is leaving for the provider.
      window.location.assign(res.url)
    } catch (error) {
      setLoadingProvider(null)
      console.error(`Social login error (${provider}):`, error)
      setFailure(
        t('auth.login.providerFailed', 'Could not sign in with {provider}. Try again.', {
          provider: identityProviderLabel(provider, t),
        })
      )
    }
  }

  /**
   * Handle SSO login (Entra ID, Okta, Google Workspace)
   */
  async function handleSSOLogin(provider: SSOProviderType) {
    if (!ssoOrg) return
    startAttempt()
    setLoadingSSOProvider(provider)
    try {
      const res = await initiateSSOLogin(provider, ssoOrg, safeRedirectTo, reauth)
      if (!res.ok || !isHttpsUrl(res.url)) throw new Error('start_failed')
      window.location.assign(res.url)
    } catch (error) {
      setLoadingSSOProvider(null)
      console.error(`SSO login error (${provider}):`, error)
      setFailure(
        t('auth.login.providerFailed', 'Could not sign in with {provider}. Try again.', {
          provider: identityProviderLabel(provider, t),
        })
      )
    }
  }

  const isLoading = isPending || loadingProvider !== null || loadingSSOProvider !== null

  const pendingDeletionDialog = pendingDeletion && (
    <PendingDeletionDialog
      organizations={pendingDeletion.organizations}
      onCancelled={async (org) => {
        // Reopened: open it now.
        const res = await selectTenantAction(org.id)
        if (res.success) {
          hardNavigate(safeRedirectTo)
          return
        }
        setPendingDeletion(null)
        toast.info(t('auth.pendingDeletion.signInAgain', 'Sign in again to open it.'))
      }}
      onContinue={() => {
        const { result } = pendingDeletion
        setPendingDeletion(null)
        handleLoginResult({ ...result, pendingDeletion: undefined })
      }}
    />
  )

  if (mfaPurpose) {
    return (
      <div className={cn('flex flex-col gap-3.5', className)}>
        {pendingDeletionDialog}
        <MfaStep
          headingLevel={1}
          purpose={mfaPurpose}
          orgs={mfaOrgs}
          onDone={handleLoginResult}
          onCancel={(message) => {
            setMfaPurpose(null)
            if (message) {
              setAttempted(true)
              setFailure(message)
            }
          }}
        />
      </div>
    )
  }

  return (
    <Form {...form}>
      {pendingDeletionDialog}
      <form
        method="post"
        onSubmit={form.handleSubmit(onSubmit)}
        className={cn('flex flex-col gap-3.5', className)}
        aria-describedby={notice ? noticeId : undefined}
        {...props}
      >
        {notice && (
          <EntryBanner
            key={notice.text}
            id={noticeId}
            tone={notice.tone}
            data-testid="login-notice"
          >
            <p>{notice.text}</p>
          </EntryBanner>
        )}

        {accountExists && (
          <EntryBanner
            tone="warn"
            data-testid="login-account-exists"
            title={t('auth.accountExists.title')}
          >
            <p>{errorMessage}</p>
            <TextLink href="/forgot-password" variant="inline">
              {t('auth.accountExists.resetPassword')}
            </TextLink>
          </EntryBanner>
        )}

        {useOrgSso && (
          <EntryBanner
            tone="info"
            data-testid="login-use-org-sso"
            title={t('auth.useOrgSso.title')}
          >
            <p>{errorMessage}</p>
            <p>{t('auth.useOrgSso.hint')}</p>
          </EntryBanner>
        )}

        {/* Email Field */}
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('auth.login.email', 'Email')}</FormLabel>
              <FormControl>
                <Input
                  placeholder="name@example.com"
                  type="email"
                  autoComplete="email"
                  disabled={isLoading}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Password Field */}
        <FormField
          control={form.control}
          name="password"
          render={({ field }) => (
            <FormItem>
              <div className="flex items-baseline justify-between gap-2">
                <FormLabel>{t('auth.login.password', 'Password')}</FormLabel>
                <TextLink href="/forgot-password" variant="inline" className="text-dense">
                  {t('auth.login.forgotPassword', 'Forgot password?')}
                </TextLink>
              </div>
              <FormControl>
                <PasswordInput
                  placeholder={t('auth.login.passwordPlaceholder', 'Enter your password')}
                  autoComplete="current-password"
                  disabled={isLoading}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {captchaRequired && authProviders?.captcha_site_key && (
          <TurnstileWidget
            siteKey={authProviders.captcha_site_key}
            onToken={setCaptchaToken}
            resetSignal={captchaReset}
          />
        )}

        {unverifiedEmail && <ResendVerification email={unverifiedEmail} />}

        {/* Submit Button */}
        <Button variant="signal" disabled={isLoading} type="submit">
          {isPending ? <Loader2 aria-hidden className="size-4 animate-spin" /> : null}
          {t('auth.login.submit', 'Sign in')}
        </Button>

        {/* Social sign-in: only providers the backend has configured; the
            block keeps its place while that answer loads. */}
        {showSocialLogin && (
          <SocialProviderButtons
            providers={authProviders}
            failed={!!authProvidersError}
            divider={t('auth.login.orContinueWith', 'Or continue with')}
            disabled={isLoading}
            loadingProvider={loadingProvider}
            onSelect={handleSocialLogin}
          />
        )}

        {/* SSO Providers (when ?org= parameter is present) */}
        {ssoOrg && ssoProviders && ssoProviders.length > 0 && (
          <>
            <EntryDivider>{t('auth.login.ssoSection', 'Organization SSO')}</EntryDivider>

            <div className="grid gap-2">
              {ssoProviders.map((provider) => {
                const label = t('auth.login.signInWith', 'Sign in with {provider}', {
                  provider: provider.display_name,
                })
                // min-w-0 + truncate: an identity provider's long display name
                // ends in an ellipsis instead of widening the card past its edge.
                return (
                  <Button
                    key={provider.id}
                    variant="outline"
                    type="button"
                    disabled={isLoading}
                    onClick={() => handleSSOLogin(provider.provider)}
                    className="w-full min-w-0"
                    title={label}
                  >
                    {loadingSSOProvider === provider.provider ? (
                      <Loader2 aria-hidden className="size-4 animate-spin" />
                    ) : (
                      <KeyRound aria-hidden className="size-4" />
                    )}
                    <span className="truncate">{label}</span>
                  </Button>
                )
              })}
            </div>
          </>
        )}
      </form>
    </Form>
  )
}
