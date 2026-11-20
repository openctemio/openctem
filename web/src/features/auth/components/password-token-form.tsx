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
import { ArrowLeft, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { EntryActions, EntryBanner, EntryCard, EntryHeader } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { TextLink } from '@/components/ui/text-link'
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
import { safeHref } from '@/lib/safe-href'

import { resetPasswordSchema, type ResetPasswordInput } from '../schemas/auth.schema'
import { authErrorText } from '../lib/auth-error-codes'
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

/** The API's codes for a link that is expired, used or not valid. */
const STALE_LINK_CODES: ReadonlySet<string> = new Set([
  'INVALID_RESET_TOKEN',
  'INVALID_VERIFICATION_TOKEN',
  'TOKEN_INVALID',
])

function isStaleLinkError(code: string | null) {
  return code !== null && STALE_LINK_CODES.has(code)
}

export function PasswordTokenForm({ mode, token }: { mode: PasswordTokenMode; token: string }) {
  const copy = useModeCopy(mode)
  const { t } = useTranslation()

  if (!token) {
    return (
      <EntryCard>
        <EntryHeader title={copy.invalidTitle} description={copy.invalidDescription} />
        <EntryActions>
          {/* The one way on is the card's main action. */}
          <Button variant="signal" asChild>
            {copy.newLink ? (
              <Link href={copy.newLink.href}>{copy.newLink.label}</Link>
            ) : (
              <Link href="/login">{t('auth.common.backToSignIn', 'Back to sign in')}</Link>
            )}
          </Button>
        </EntryActions>
      </EntryCard>
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
  const [errorCode, setErrorCode] = useState<string | null>(null)
  const [revokeKeys, setRevokeKeys] = useState(true)

  const passwordPolicy = usePasswordPolicy()
  const form = useForm<ResetPasswordInput>({
    resolver: translatingResolver(zodResolver(resetPasswordSchema), t),
    defaultValues: { password: '', confirmPassword: '', token },
  })

  function onSubmit(data: ResetPasswordInput) {
    setError(null)
    setErrorCode(null)
    const issue = passwordPolicy && passwordPolicyIssue(data.password, passwordPolicy, t)
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
        // The words come from the API's code; the server's sentence is never shown.
        const code = 'code' in result && typeof result.code === 'string' ? result.code : null
        const errorMessage = authErrorText(
          code,
          t,
          t(`auth.passwordToken.${mode}.failed`, `${PASSWORD_TOKEN_COPY[mode].submit} failed`)
        )
        setError(errorMessage)
        setErrorCode(code)
        // A setup link only comes from an administrator: the toast says what the
        // banner says, never "request a new one".
        toast.error(isStaleLinkError(code) && !copy.newLink ? copy.newLinkHint : errorMessage)
      }
    })
  }

  if (isSuccess) {
    return (
      <EntryCard>
        <EntryHeader title={copy.successTitle} />
        <EntryBanner tone="ok">{copy.successDescription}</EntryBanner>
        <EntryActions>
          <Button variant="signal" asChild>
            <Link href="/login">
              {mode === 'setup'
                ? t('auth.passwordToken.signIn', 'Sign in')
                : t('auth.common.backToSignIn', 'Back to sign in')}
            </Link>
          </Button>
        </EntryActions>
      </EntryCard>
    )
  }

  return (
    <EntryCard>
      <EntryHeader title={copy.title} description={copy.description} />
      <Form {...form}>
        <form
          method="post"
          onSubmit={form.handleSubmit(onSubmit)}
          className="flex flex-col gap-3.5"
        >
          {error &&
            (isStaleLinkError(errorCode) && !copy.newLink ? (
              // A setup link only comes from an administrator: say so instead of
              // the generic "request a new one", which has no page to go to.
              <EntryBanner tone="danger" role="alert" title={copy.invalidTitle}>
                <p>{copy.newLinkHint}</p>
              </EntryBanner>
            ) : (
              <EntryBanner tone="danger" role="alert">
                <p>{error}</p>
                {isStaleLinkError(errorCode) && copy.newLink && (
                  <TextLink href={safeHref(copy.newLink.href)} variant="inline">
                    {copy.newLink.label}
                  </TextLink>
                )}
              </EntryBanner>
            ))}

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
                <FormLabel>{t('auth.passwordToken.confirmPassword', 'Confirm password')}</FormLabel>
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

          <EntryActions>
            <Button variant="signal" disabled={isPending} type="submit">
              {isPending ? <Loader2 aria-hidden className="size-4 animate-spin" /> : null}
              {copy.submit}
            </Button>
            <Button variant="outline" asChild>
              <Link href="/login">
                <ArrowLeft aria-hidden className="size-4" />
                {t('auth.common.backToSignIn', 'Back to sign in')}
              </Link>
            </Button>
          </EntryActions>
        </form>
      </Form>
    </EntryCard>
  )
}
