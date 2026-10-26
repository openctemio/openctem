'use client'

import { useState, useTransition } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import Link from '@/components/link'
import { ArrowLeft, Loader2, Mail } from 'lucide-react'
import { toast } from 'sonner'

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
import { Input } from '@/components/ui/input'

import { forgotPasswordSchema, type ForgotPasswordInput } from '@/features/auth/schemas/auth.schema'
import { translatingResolver } from '@/features/auth/lib/translating-resolver'
import { forgotPasswordAction } from '@/features/auth/actions/local-auth-actions'
import { usePasswordPolicy } from '@/features/auth/api/use-auth-providers'
import { formatLinkLifetime } from '@/features/auth/lib/password-policy'
import { useTranslation } from '@/context/i18n-provider'

export default function ForgotPasswordPage() {
  const [isPending, startTransition] = useTransition()
  const [isSubmitted, setIsSubmitted] = useState(false)
  const passwordPolicy = usePasswordPolicy()
  const { t } = useTranslation()

  const form = useForm<ForgotPasswordInput>({
    resolver: translatingResolver(zodResolver(forgotPasswordSchema), t),
    defaultValues: {
      email: '',
    },
  })

  function onSubmit(data: ForgotPasswordInput) {
    startTransition(async () => {
      const result = await forgotPasswordAction(data.email)

      if (result.success) {
        setIsSubmitted(true)
        toast.success(result.message)
      } else {
        toast.error(
          'error' in result ? result.error : t('auth.forgot.failed', 'Something went wrong')
        )
      }
    })
  }

  if (isSubmitted) {
    return (
      <Card className="gap-4">
        <CardHeader>
          <CardTitle className="text-lg tracking-tight">
            <h1>{t('auth.forgot.sentTitle', 'Check your email')}</h1>
          </CardTitle>
          <CardDescription>
            {t(
              'auth.forgot.sentBody',
              "If an account exists with the email you entered, we've sent a password reset link. Please check your inbox and spam folder."
            )}
            {passwordPolicy &&
              ' ' +
                t('auth.forgot.expiresIn', 'The link expires in {lifetime}.', {
                  lifetime: formatLinkLifetime(passwordPolicy.reset_link_valid_minutes),
                })}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <Button variant="outline" asChild>
            <Link href="/login">
              <ArrowLeft className="h-4 w-4" />
              {t('auth.common.backToSignIn', 'Back to sign in')}
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
          <h1>{t('auth.forgot.title', 'Forgot password')}</h1>
        </CardTitle>
        <CardDescription>
          {t(
            'auth.forgot.description',
            "Enter your email address and we'll send you a link to reset your password."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="grid gap-3">
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('auth.forgot.email', 'Email')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="name@example.com"
                      type="email"
                      autoComplete="email"
                      disabled={isPending}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button className="mt-2" disabled={isPending} type="submit">
              {isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Mail className="h-4 w-4" />
              )}
              {t('auth.forgot.submit', 'Send reset link')}
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
