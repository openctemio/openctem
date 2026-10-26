/**
 * Choose a password from a one-time token.
 *
 * Two flows share this form and the same API call
 * (POST /auth/reset-password {token, new_password}):
 * - "reset": the forgot-password email link (/reset-password#token=...)
 * - "setup": the one-time link an administrator gives a user they created
 *   (/set-password#token=...)
 * Only the wording and the "get a new link" advice differ.
 */

'use client'

import { useState, useTransition } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import Link from '@/components/link'
import { ArrowLeft, CheckCircle, Loader2, KeyRound } from 'lucide-react'
import { toast } from 'sonner'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { PasswordInput } from '@/components/password-input'
import { useTranslation } from '@/context/i18n-provider'

import { resetPasswordSchema, type ResetPasswordInput } from '../schemas/auth.schema'
import { translatingResolver } from '../lib/translating-resolver'
import { RevokeApiKeysOption } from './revoke-api-keys-option'
import { resetPasswordAction } from '../actions/local-auth-actions'
import { usePasswordPolicy } from '../api/use-auth-providers'
import { passwordPolicyIssue } from '../lib/password-policy'
import { PasswordPolicyHint } from './password-policy-hint'

export type PasswordTokenMode = 'reset' | 'setup'

interface ModeCopy {
  title: string
  description: string
  submit: string
  successTitle: string
  successDescription: string
  invalidTitle: string
  invalidDescription: string
  /** Where to get a new link; null when only an administrator can issue one. */
  newLink: { href: string; label: string } | null
  newLinkHint: string
}

export const PASSWORD_TOKEN_COPY: Record<PasswordTokenMode, ModeCopy> = {
  reset: {
    title: 'Reset password',
    description: 'Enter your new password below.',
    submit: 'Reset password',
    successTitle: 'Password reset',
    successDescription:
      'Your password has been updated. Your sessions were signed out and connected apps were revoked. You can now sign in with your new password.',
    invalidTitle: 'Invalid reset link',
    invalidDescription:
      'This password reset link is invalid or missing a token. Request a new one.',
    newLink: { href: '/forgot-password', label: 'Request a new reset link' },
    newLinkHint: '',
  },
  setup: {
    title: 'Set your password',
    description: 'Your administrator created an account for you. Choose a password to sign in.',
    submit: 'Set password',
    successTitle: 'Password set',
    successDescription: 'Your password is set. Sign in to continue.',
    invalidTitle: 'Invalid setup link',
    invalidDescription:
      'This setup link is invalid or missing a token. Ask your administrator for a new setup link.',
    newLink: null,
    newLinkHint: 'Setup links work once and expire. Ask your administrator for a new one.',
  },
}

/** Translates a mode's copy; the English text in PASSWORD_TOKEN_COPY is the fallback. */
function useModeCopy(mode: PasswordTokenMode): ModeCopy {
  const { t } = useTranslation()
  const c = PASSWORD_TOKEN_COPY[mode]
  const k = (field: string, fallback: string) =>
    fallback ? t(`auth.passwordToken.${mode}.${field}`, fallback) : fallback
  return {
    title: k('title', c.title),
    description: k('description', c.description),
    submit: k('submit', c.submit),
    successTitle: k('successTitle', c.successTitle),
    successDescription: k('successDescription', c.successDescription),
    invalidTitle: k('invalidTitle', c.invalidTitle),
    invalidDescription: k('invalidDescription', c.invalidDescription),
    newLink: c.newLink ? { href: c.newLink.href, label: k('newLinkLabel', c.newLink.label) } : null,
    newLinkHint: k('newLinkHint', c.newLinkHint),
  }
}

function isStaleLinkError(message: string) {
  const m = message.toLowerCase()
  return m.includes('expired') || m.includes('invalid')
}

export function PasswordTokenForm({ mode, token }: { mode: PasswordTokenMode; token: string }) {
  const copy = useModeCopy(mode)
  const { t } = useTranslation()

  if (!token) {
    return (
      <Card className="gap-4">
        <CardHeader>
          <CardTitle className="text-lg tracking-tight">
            <h1>{copy.invalidTitle}</h1>
          </CardTitle>
          <CardDescription>{copy.invalidDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" asChild>
            {copy.newLink ? (
              <Link href={copy.newLink.href}>{copy.newLink.label}</Link>
            ) : (
              <Link href="/login">
                <ArrowLeft className="h-4 w-4" />
                {t('auth.common.backToSignIn', 'Back to sign in')}
              </Link>
            )}
          </Button>
        </CardContent>
      </Card>
    )
  }

  // The page reads the token from the URL after hydration, so the first render
  // has none. Mount the form only once the token is known (keyed by it), so the
  // form state carries the real token instead of the empty first-render value.
  return <TokenPasswordForm key={token} mode={mode} token={token} />
}

function TokenPasswordForm({ mode, token }: { mode: PasswordTokenMode; token: string }) {
  const copy = useModeCopy(mode)
  const { t } = useTranslation()
  const [isPending, startTransition] = useTransition()
  const [isSuccess, setIsSuccess] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [revokeKeys, setRevokeKeys] = useState(true)

  const passwordPolicy = usePasswordPolicy()
  const form = useForm<ResetPasswordInput>({
    resolver: translatingResolver(zodResolver(resetPasswordSchema), t),
    defaultValues: { password: '', confirmPassword: '', token },
  })

  function onSubmit(data: ResetPasswordInput) {
    setError(null)
    const issue = passwordPolicy && passwordPolicyIssue(data.password, passwordPolicy)
    if (issue) {
      form.setError('password', { message: issue })
      return
    }
    startTransition(async () => {
      const result = await resetPasswordAction(
        data.token,
        data.password,
        mode === 'reset' && revokeKeys
      )
      if (result.success) {
        setIsSuccess(true)
        toast.success(copy.successDescription)
      } else {
        const errorMessage =
          'error' in result
            ? result.error
            : t(`auth.passwordToken.${mode}.failed`, `${PASSWORD_TOKEN_COPY[mode].submit} failed`)
        setError(errorMessage)
        toast.error(errorMessage)
      }
    })
  }

  if (isSuccess) {
    return (
      <Card className="gap-4">
        <CardHeader>
          <div className="text-primary mb-2 flex justify-center">
            <CheckCircle className="h-10 w-10" />
          </div>
          <CardTitle className="text-center text-lg tracking-tight">
            <h1>{copy.successTitle}</h1>
          </CardTitle>
          <CardDescription className="text-center">{copy.successDescription}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild className="w-full">
            <Link href="/login">
              <ArrowLeft className="h-4 w-4" />
              {mode === 'setup'
                ? t('auth.passwordToken.signIn', 'Sign in')
                : t('auth.common.backToSignIn', 'Back to sign in')}
            </Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="text-lg tracking-tight">
          <h1>{copy.title}</h1>
        </CardTitle>
        <CardDescription>{copy.description}</CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form method="post" onSubmit={form.handleSubmit(onSubmit)} className="grid gap-3">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>
                  <p>{error}</p>
                  {isStaleLinkError(error) &&
                    (copy.newLink ? (
                      <Link
                        href={copy.newLink.href}
                        className="text-primary hover:text-primary/80 mt-2 inline-block text-sm underline underline-offset-4"
                      >
                        {copy.newLink.label}
                      </Link>
                    ) : (
                      <p className="mt-2">{copy.newLinkHint}</p>
                    ))}
                </AlertDescription>
              </Alert>
            )}

            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {mode === 'setup'
                      ? t('auth.passwordToken.password', 'Password')
                      : t('auth.passwordToken.newPassword', 'New password')}
                  </FormLabel>
                  <FormControl>
                    <PasswordInput
                      placeholder={
                        mode === 'setup'
                          ? t('auth.passwordToken.choosePassword', 'Choose a password')
                          : t('auth.passwordToken.enterNewPassword', 'Enter new password')
                      }
                      autoComplete="new-password"
                      disabled={isPending}
                      {...field}
                    />
                  </FormControl>
                  <PasswordPolicyHint />
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="confirmPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {t('auth.passwordToken.confirmPassword', 'Confirm password')}
                  </FormLabel>
                  <FormControl>
                    <PasswordInput
                      placeholder={t('auth.passwordToken.confirmPassword', 'Confirm password')}
                      autoComplete="new-password"
                      disabled={isPending}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {mode === 'reset' && (
              <RevokeApiKeysOption
                id="reset-revoke-keys"
                checked={revokeKeys}
                onCheckedChange={setRevokeKeys}
                disabled={isPending}
              />
            )}

            <Button className="mt-2" disabled={isPending} type="submit">
              {isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <KeyRound className="h-4 w-4" />
              )}
              {copy.submit}
            </Button>

            <Button variant="link" size="sm" asChild className="mt-1">
              <Link href="/login">
                <ArrowLeft className="h-4 w-4" />
                {t('auth.common.backToSignIn', 'Back to sign in')}
              </Link>
            </Button>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}
