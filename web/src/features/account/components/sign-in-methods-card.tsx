'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Building2, KeyRound, Link2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { IconGithub, IconGoogle, IconMicrosoft } from '@/assets/brand-icons'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { StepUpDialog, stepUpProofErrorMessage, type StepUpProofInput } from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
import { describeAuthCode } from '@/features/auth/lib/auth-error-codes'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'

import {
  useLinkProvider,
  useSignInMethods,
  useUnlinkIdentity,
  type SignInMethod,
} from '../api/use-sign-in-methods'
import { LINK_PROVIDERS, readLinkResult, type LinkProvider } from '../lib/link-result'
import { linkProofFrom } from '../lib/link-proof'

const PROVIDER_ICON: Record<LinkProvider, typeof IconGoogle> = {
  google: IconGoogle,
  github: IconGithub,
  microsoft: IconMicrosoft,
}

const PROVIDER_NAME: Record<LinkProvider, string> = {
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
}

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code
  return typeof code === 'string' ? code : undefined
}

/**
 * Account > Security, "Connected sign-in methods": link or unlink Google,
 * GitHub and Microsoft sign-in. Each link and unlink asks, in its confirm
 * dialog, for the authenticator code (or the password when two-factor
 * authentication is off); a recent sign-in does not count. An account with
 * neither is told to turn on two-factor authentication first. The account's
 * last way to sign in cannot be removed. Hidden when the platform offers no
 * social sign-in.
 */
export function SignInMethodsCard() {
  const { t } = useTranslation()
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const { methods, isLoading, isError, mutate } = useSignInMethods()
  const { link, linking } = useLinkProvider()
  const { unlink, isUnlinking } = useUnlinkIdentity()
  const [toUnlink, setToUnlink] = useState<SignInMethod | null>(null)
  const [toLink, setToLink] = useState<LinkProvider | null>(null)

  // The result of a link round trip, once, then a clean address.
  const query = searchParams.toString()
  const result = useMemo(() => readLinkResult(new URLSearchParams(query)), [query])
  const handled = useRef('')
  useEffect(() => {
    if (!result) {
      handled.current = ''
      return
    }
    // The effect also re-runs when t/mutate change identity: handle each result once.
    const resultKey = JSON.stringify(result)
    if (handled.current === resultKey) return
    handled.current = resultKey
    if (result.kind === 'linked') {
      toast.success(
        t('account.signInMethods.linked', '{provider} is linked. You can sign in with it now.', {
          provider: PROVIDER_NAME[result.provider],
        })
      )
      mutate()
    } else {
      toast.error(
        describeAuthCode(result.code, t) ??
          t('account.signInMethods.linkFailed', 'The provider could not be linked. Try again.')
      )
    }
    router.replace(pathname)
  }, [result, mutate, router, pathname, t])

  if (isError || (!isLoading && !methods)) return null
  const social = methods?.identities.filter((m) => m.provider !== 'organization') ?? []
  const organization = methods?.identities.filter((m) => m.provider === 'organization') ?? []
  const shown = LINK_PROVIDERS.filter(
    (p) => methods?.available.includes(p) || social.some((m) => m.provider === p)
  )
  if (!isLoading && shown.length === 0) return null

  const proofKind = methods?.proof ?? ''
  const proofHint =
    proofKind === 'password'
      ? t('account.signInMethods.proofPassword', 'Enter your password to confirm.')
      : t(
          'account.signInMethods.proofCode',
          'Enter the code from your authenticator app to confirm.'
        )
  // Refusals are shown in the dialog, which clears the field for another try.
  const proofError = (fallback: string) => (err: unknown) =>
    describeAuthCode(errorCode(err), t) ??
    (errorCode(err) ? getErrorMessage(err, fallback) : stepUpProofErrorMessage(t, err))
  const noProofNotice = (close: () => void) =>
    proofKind
      ? undefined
      : {
          body: (
            <p className="text-sm">
              {t(
                'account.signInMethods.proofUnavailable',
                'Turn on two-factor authentication on this page first: changing how you sign in needs a code from your authenticator app.'
              )}
            </p>
          ),
          actions: (
            <Button type="button" variant="outline" onClick={close}>
              {t('account.signInMethods.close', 'Close')}
            </Button>
          ),
        }

  async function confirmLink(input: StepUpProofInput) {
    const proof = linkProofFrom(input)
    if (!toLink || !proof) return
    // Resolves only on failure: on success the page goes to the provider.
    await link(toLink, proof)
  }

  async function confirmUnlink(input: StepUpProofInput) {
    const proof = linkProofFrom(input)
    if (!toUnlink || !proof) return
    await unlink(toUnlink.id, proof)
    toast.success(
      t('account.signInMethods.unlinked', '{provider} is no longer linked.', {
        provider: PROVIDER_NAME[toUnlink.provider as LinkProvider],
      })
    )
    setToUnlink(null)
    mutate()
  }

  return (
    <Card data-testid="sign-in-methods-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link2 className="h-5 w-5" />
          {t('account.signInMethods.title', 'Connected sign-in methods')}
        </CardTitle>
        <CardDescription>
          {t(
            'account.signInMethods.description',
            'Sign in with Google, GitHub or Microsoft as well as your password. Your two-factor authentication still applies. Linking or unlinking asks you to confirm it is you.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : (
          <ul className="divide-y rounded-md border">
            {methods?.password && (
              <li className="flex items-center justify-between gap-4 p-4">
                <div className="flex items-center gap-3">
                  <KeyRound className="h-5 w-5 text-muted-foreground" />
                  <span className="font-medium">
                    {t('account.signInMethods.password', 'Password')}
                  </span>
                </div>
                <Badge variant="secondary">{t('account.signInMethods.inUse', 'In use')}</Badge>
              </li>
            )}
            {shown.map((provider) => {
              const Icon = PROVIDER_ICON[provider]
              const linked = social.find((m) => m.provider === provider)
              return (
                <li
                  key={provider}
                  className="flex items-center justify-between gap-4 p-4"
                  data-testid={`sign-in-method-${provider}`}
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <Icon className="h-5 w-5 shrink-0" />
                    <div className="min-w-0 space-y-0.5">
                      <span className="font-medium">{PROVIDER_NAME[provider]}</span>
                      <p className="text-sm text-muted-foreground">
                        {linked
                          ? t('account.signInMethods.linkedOn', 'Linked {date}', {
                              date: formatDateSafe(linked.created_at),
                            })
                          : t('account.signInMethods.notLinked', 'Not linked')}
                      </p>
                      {linked && !linked.unlinkable && (
                        <p className="text-sm text-muted-foreground">
                          {t(
                            'account.signInMethods.onlyMethod',
                            'This is your only way to sign in, so it cannot be removed.'
                          )}
                        </p>
                      )}
                    </div>
                  </div>
                  {linked ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="shrink-0 text-destructive hover:text-destructive"
                      disabled={!linked.unlinkable}
                      onClick={() => setToUnlink(linked)}
                      aria-label={t('account.signInMethods.unlinkProvider', 'Unlink {provider}', {
                        provider: PROVIDER_NAME[provider],
                      })}
                    >
                      {t('account.signInMethods.unlink', 'Unlink')}
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      className="shrink-0"
                      disabled={linking !== null}
                      onClick={() => setToLink(provider)}
                      aria-label={t('account.signInMethods.linkProvider', 'Link {provider}', {
                        provider: PROVIDER_NAME[provider],
                      })}
                    >
                      {linking === provider && <Loader2 className="h-4 w-4 animate-spin" />}
                      {t('account.signInMethods.link', 'Link')}
                    </Button>
                  )}
                </li>
              )
            })}
            {organization.map((m) => (
              <li key={m.id} className="flex items-center justify-between gap-4 p-4">
                <div className="flex items-center gap-3">
                  <Building2 className="h-5 w-5 text-muted-foreground" />
                  <div className="space-y-0.5">
                    <span className="font-medium">
                      {t('account.signInMethods.organization', 'Organization single sign-on')}
                    </span>
                    <p className="text-sm text-muted-foreground">
                      {t(
                        'account.signInMethods.organizationManaged',
                        'Managed by your organization'
                      )}
                    </p>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <StepUpDialog
        open={!!toLink}
        onOpenChange={(open) => !open && setToLink(null)}
        title={t('account.signInMethods.linkTitle', 'Link {provider}', {
          provider: toLink ? PROVIDER_NAME[toLink] : '',
        })}
        description={`${t('account.signInMethods.linkDesc', 'Next you sign in to {provider}, then come back here.', { provider: toLink ? PROVIDER_NAME[toLink] : '' })}${proofKind ? ` ${proofHint}` : ''}`}
        factor={proofKind === 'password' ? 'password' : 'totp'}
        submitLabel={t('account.signInMethods.link', 'Link')}
        onSubmit={confirmLink}
        errorMessage={proofError(
          t('account.signInMethods.linkFailed', 'The provider could not be linked. Try again.')
        )}
        notice={noProofNotice(() => setToLink(null))}
      />

      <StepUpDialog
        open={!!toUnlink}
        onOpenChange={(open) => !open && !isUnlinking && setToUnlink(null)}
        title={t('account.signInMethods.unlinkTitle', 'Unlink {provider}?', {
          provider: toUnlink ? PROVIDER_NAME[toUnlink.provider as LinkProvider] : '',
        })}
        description={`${t(
          'account.signInMethods.unlinkDesc',
          'You will no longer be able to sign in with it. You can link it again later.'
        )}${proofKind ? ` ${proofHint}` : ''}`}
        factor={proofKind === 'password' ? 'password' : 'totp'}
        submitLabel={t('account.signInMethods.unlink', 'Unlink')}
        destructive
        onSubmit={confirmUnlink}
        errorMessage={proofError(
          t('account.signInMethods.unlinkFailed', 'The provider could not be unlinked.')
        )}
        notice={noProofNotice(() => setToUnlink(null))}
      />
    </Card>
  )
}
