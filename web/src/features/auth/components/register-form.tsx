/**
 * Register Form Component
 *
 * Handles user registration with support for:
 * - Local auth (email/password) via backend API
 * - Social auth (Google, GitHub, Microsoft) via OAuth2
 */

'use client'

import { loginErrorMessage } from '@/features/auth/lib/login-error'
import { NOT_SET_UP_PATH, isSignupNotAvailable } from '@/features/auth/lib/signup-outcome'
import { useTranslation } from '@/context/i18n-provider'
import { useEffect, useMemo, useState, useTransition } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useRouter, useSearchParams } from 'next/navigation'
import { Loader2, UserPlus } from 'lucide-react'
import { toast } from 'sonner'

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
import { PasswordInput } from '@/components/password-input'
import { IconGoogle, IconGithub, IconMicrosoft } from '@/assets/brand-icons'

// Import schema and server actions
import { registerSchema, type RegisterInput } from '../schemas/auth.schema'
import { passwordPolicyIssue } from '../lib/password-policy'
import { PasswordPolicyHint } from './password-policy-hint'
import { registerAction } from '../actions/local-auth-actions'
import { initiateSocialLogin, type SocialProvider } from '../actions/social-auth-actions'
import { useAuthProviders } from '../api/use-auth-providers'
import { invitationTokenFromReturnTo } from '../lib/self-register'
import { identityProviderLabel } from '@/lib/identity-provider-label'

// ============================================
// TYPES
// ============================================

interface RegisterFormProps extends React.HTMLAttributes<HTMLFormElement> {
  /**
   * URL to redirect to after successful registration
   * @default '/login'
   */
  redirectTo?: string

  /**
   * URL to redirect to after social login (which signs in directly)
   * @default '/'
   */
  socialRedirectTo?: string

  /**
   * Whether to show social login buttons (Google, GitHub, Microsoft)
   * @default true
   */
  showSocialLogin?: boolean
}

// ============================================
// SOCIAL PROVIDERS CONFIG
// ============================================

const socialProviders: {
  id: SocialProvider
  name: string
  icon: React.ComponentType<{ className?: string }>
}[] = [
  { id: 'google', name: 'Google', icon: IconGoogle },
  { id: 'github', name: 'GitHub', icon: IconGithub },
  { id: 'microsoft', name: 'Microsoft', icon: IconMicrosoft },
]

// ============================================
// COMPONENT
// ============================================

export function RegisterForm({
  className,
  redirectTo = '/login',
  socialRedirectTo = '/',
  showSocialLogin = true,
  ...props
}: RegisterFormProps) {
  const [isPending, startTransition] = useTransition()
  const [loadingProvider, setLoadingProvider] = useState<SocialProvider | null>(null)
  const router = useRouter()
  const searchParams = useSearchParams()

  // Only render buttons that lead somewhere. This form mapped over
  // socialProviders unconditionally, so all three rendered on every
  // deployment — including the ones with no OAuth credentials, where the
  // button dead-ends. LoginForm has always asked the API which providers are
  // live; this is the same question, asked here too.
  const { data: authProviders } = useAuthProviders()
  const passwordPolicy = authProviders?.password_policy
  const enabledSocialProviders = authProviders
    ? socialProviders.filter((provider) => authProviders.social?.[provider.id])
    : []

  // Error code from an OAuth callback. Only a known code's message is shown,
  // never the raw parameter, and once per value (this ran on every render).
  const errorParam = searchParams.get('error')
  const { t } = useTranslation()
  const loginError = errorParam ? loginErrorMessage(errorParam) : null
  const errorMessage = loginError ? t(loginError.key, loginError.fallback) : null
  useEffect(() => {
    if (errorMessage) toast.error(errorMessage)
  }, [errorMessage])

  // Pre-fill the email field when the user arrives from an invitation
  // link. The invitation page redirects to /login?email=alice@co.com&
  // returnTo=/invitations, and the "Create Account" link on
  // the login page preserves the email param. Without this the user
  // has to manually re-type the exact email the invitation was sent
  // to — error-prone and high friction.
  const prefillEmail = searchParams.get('email') ?? ''

  // Extract the invitation token from the returnTo param if it points
  // at an invitation page. The backend uses this to apply the inviting
  // tenant's email-verification rule (e.g. "never") to the new user
  // instead of falling back to the platform default. Without this,
  // setting EmailVerificationMode=never on a tenant has no effect for
  // brand-new users who don't yet have a membership in any tenant.
  //
  // With open registration disabled (the default), this token is also what
  // lets an invited person create their account at all.
  const returnTo = searchParams.get('returnTo')
  const invitationToken = useMemo(() => invitationTokenFromReturnTo(returnTo), [returnTo])

  // Form setup with centralized schema
  const form = useForm<RegisterInput>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      firstName: '',
      lastName: '',
      email: prefillEmail,
      password: '',
      confirmPassword: '',
    },
  })

  /**
   * Handle form submission for local auth
   */
  function onSubmit(data: RegisterInput) {
    const issue = passwordPolicy && passwordPolicyIssue(data.password, passwordPolicy)
    if (issue) {
      form.setError('password', { message: issue })
      return
    }
    startTransition(async () => {
      const result = await registerAction({
        email: data.email,
        password: data.password,
        firstName: data.firstName,
        lastName: data.lastName,
        invitationToken,
      })

      if (result.success) {
        toast.success(
          result.message ||
            'Registration successful! Please check your email to verify your account.'
        )
        // Invited: sign in and land back on the invitation to accept it.
        router.push(
          invitationToken && returnTo
            ? `/login?returnTo=${encodeURIComponent(returnTo)}&email=${encodeURIComponent(data.email)}`
            : redirectTo
        )
      } else if (isSignupNotAvailable(result.code)) {
        // The sign-up policy refused: the one "not set up" page.
        router.push(NOT_SET_UP_PATH)
      } else {
        toast.error(result.error || 'Registration failed')
      }
    })
  }

  /**
   * Handle social login (Google, GitHub, Microsoft)
   * Social login also handles registration - creates account if doesn't exist
   */
  async function handleSocialLogin(provider: SocialProvider) {
    setLoadingProvider(provider)
    try {
      // This will redirect to the OAuth provider
      await initiateSocialLogin(provider, socialRedirectTo)
    } catch (error) {
      setLoadingProvider(null)
      console.error(`Social login error (${provider}):`, error)
      toast.error(`Failed to sign up with ${identityProviderLabel(provider)}. Please try again.`)
    }
  }

  const isLoading = isPending || loadingProvider !== null

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(onSubmit)}
        className={cn('grid gap-3', className)}
        {...props}
      >
        {/* Social Login Section - Show First for Better UX */}
        {showSocialLogin && enabledSocialProviders.length > 0 && (
          <>
            <div
              className="grid gap-2"
              style={{
                gridTemplateColumns: `repeat(${enabledSocialProviders.length}, minmax(0, 1fr))`,
              }}
            >
              {enabledSocialProviders.map((provider) => (
                <Button
                  key={provider.id}
                  variant="outline"
                  type="button"
                  disabled={isLoading}
                  onClick={() => handleSocialLogin(provider.id)}
                  className="relative"
                >
                  {loadingProvider === provider.id ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <provider.icon className="h-4 w-4" />
                  )}
                  <span className="sr-only">{provider.name}</span>
                </Button>
              ))}
            </div>

            <div className="relative my-2">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background text-muted-foreground px-2">
                  Or register with email
                </span>
              </div>
            </div>
          </>
        )}

        {/* Name Fields */}
        <div className="grid grid-cols-2 gap-3">
          <FormField
            control={form.control}
            name="firstName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>First Name</FormLabel>
                <FormControl>
                  <Input
                    placeholder="John"
                    autoComplete="given-name"
                    disabled={isLoading}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="lastName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Last Name</FormLabel>
                <FormControl>
                  <Input
                    placeholder="Doe"
                    autoComplete="family-name"
                    disabled={isLoading}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* Email Field */}
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email</FormLabel>
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
              <FormLabel>Password</FormLabel>
              <FormControl>
                <PasswordInput
                  placeholder="Create a password"
                  autoComplete="new-password"
                  disabled={isLoading}
                  {...field}
                />
              </FormControl>
              <PasswordPolicyHint />
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Confirm Password Field */}
        <FormField
          control={form.control}
          name="confirmPassword"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Confirm Password</FormLabel>
              <FormControl>
                <PasswordInput
                  placeholder="Confirm your password"
                  autoComplete="new-password"
                  disabled={isLoading}
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {/* Submit Button */}
        <Button className="mt-2" disabled={isLoading} type="submit">
          {isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <UserPlus className="h-4 w-4" />
          )}
          Create Account
        </Button>
      </form>
    </Form>
  )
}
