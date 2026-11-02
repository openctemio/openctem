'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Building2, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { StepUpDialog, stepUpProofErrorMessage, type StepUpProofInput } from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
import { describeAuthCode } from '@/features/auth/lib/auth-error-codes'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe } from '@/lib/format-date'

import {
  useSSOLinks,
  useStartSSOLink,
  useUnlinkSSOIdentity,
  type SSOLinkedIdentity,
  type SSOLinkOrganization,
} from '../api/use-sso-links'
import { readSSOLinkResult } from '../lib/link-result'
import { linkProofFrom } from '../lib/link-proof'
import { SignInMethodRow } from './sign-in-method-row'

function errorCode(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code
  return typeof code === 'string' ? code : undefined
}

type UnlinkTarget = { identity: SSOLinkedIdentity; name: string }

/**
 * Account > Security, "Organization sign-in": link the single sign-on of an
 * organization the person belongs to, so they can sign in through its
 * identity provider (the way an organization that requires single sign-on
 * expects), or unlink it. Each link and unlink asks, in its confirm dialog,
 * for the authenticator code (or the password when two-factor authentication
 * is off); the identity provider then asks the person to sign in again.
 * Hidden when no organization of the person has single sign-on.
 */
export function OrganizationSignInCard() {
  const { t } = useTranslation()
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const { links, isLoading, isError, mutate } = useSSOLinks()
  const { link, linking } = useStartSSOLink()
  const { unlink, isUnlinking } = useUnlinkSSOIdentity()
  const [toLink, setToLink] = useState<SSOLinkOrganization | null>(null)
  const [toUnlink, setToUnlink] = useState<UnlinkTarget | null>(null)

  // The result of a link round trip, once, then a clean address.
  const query = searchParams.toString()
  const result = useMemo(() => readSSOLinkResult(new URLSearchParams(query)), [query])
  const handled = useRef('')
  useEffect(() => {
    if (!result) {
      handled.current = ''
      return
    }
    const resultKey = JSON.stringify(result)
    if (handled.current === resultKey) return
    handled.current = resultKey
    if (result.kind === 'linked') {
      toast.success(
        t(
          'account.organizationSignIn.linked',
          "Your organization's sign-in is linked. You can sign in with it now."
        )
      )
      mutate()
    } else {
      toast.error(
        describeAuthCode(result.code, t) ??
          t(
            'account.organizationSignIn.linkFailed',
            "Your organization's sign-in could not be linked. Try again."
          )
      )
    }
    router.replace(pathname)
  }, [result, mutate, router, pathname, t])

  const organizations = links?.organizations ?? []
  const other = links?.other ?? []
  if (isError || (!isLoading && organizations.length === 0 && other.length === 0)) return null

  const proofKind = links?.proof ?? ''
  const proofHint =
    proofKind === 'password'
      ? t('account.signInMethods.proofPassword', 'Enter your password to confirm.')
      : t(
          'account.signInMethods.proofCode',
          'Enter the code from your authenticator app to confirm.'
        )
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

  const statusLines = (identity?: SSOLinkedIdentity) => {
    if (!identity) return [t('account.signInMethods.notLinked', 'Not linked')]
    const lines = [
      t('account.signInMethods.linkedOn', 'Linked {date}', {
        date: formatDateSafe(identity.created_at),
      }),
    ]
    if (!identity.unlinkable) {
      lines.push(t('account.signInMethods.organizationManaged', 'Managed by your organization'))
    }
    return lines
  }

  const unlinkButton = (identity: SSOLinkedIdentity, name: string) => (
    <Button
      variant="ghost"
      size="sm"
      className="shrink-0 text-destructive hover:text-destructive"
      disabled={!identity.unlinkable}
      onClick={() => setToUnlink({ identity, name })}
      aria-label={t('account.signInMethods.unlinkProvider', 'Unlink {provider}', {
        provider: name,
      })}
    >
      {t('account.signInMethods.unlink', 'Unlink')}
    </Button>
  )

  async function confirmLink(input: StepUpProofInput) {
    const proof = linkProofFrom(input)
    if (!toLink || !proof) return
    // Resolves only on failure: on success the page goes to the identity provider.
    await link(toLink, proof)
  }

  async function confirmUnlink(input: StepUpProofInput) {
    const proof = linkProofFrom(input)
    if (!toUnlink || !proof) return
    await unlink(toUnlink.identity.id, proof)
    toast.success(
      t('account.signInMethods.unlinked', '{provider} is no longer linked.', {
        provider: toUnlink.name,
      })
    )
    setToUnlink(null)
    mutate()
  }

  const otherName = t('account.signInMethods.organization', 'Organization single sign-on')

  return (
    <Card data-testid="organization-sign-in-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Building2 className="h-5 w-5" />
          {t('account.organizationSignIn.title', 'Organization sign-in')}
        </CardTitle>
        <CardDescription>
          {t(
            'account.organizationSignIn.description',
            "Sign in through your organization's identity provider. Linking asks you to confirm it is you, then to sign in at your organization."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-14 w-full" />
        ) : (
          <ul className="divide-y rounded-md border">
            {organizations.map((org) => {
              const key = `${org.org_slug}/${org.provider}`
              return (
                <SignInMethodRow
                  key={key}
                  testId={`organization-sign-in-${org.org_slug}-${org.provider}`}
                  icon={<Building2 className="text-muted-foreground" />}
                  title={org.org_name}
                  lines={[org.display_name, ...statusLines(org.identity)]}
                  action={
                    org.identity ? (
                      unlinkButton(org.identity, org.org_name)
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        className="shrink-0"
                        disabled={linking !== null}
                        onClick={() => setToLink(org)}
                        aria-label={t('account.signInMethods.linkProvider', 'Link {provider}', {
                          provider: org.org_name,
                        })}
                      >
                        {linking === key && <Loader2 className="h-4 w-4 animate-spin" />}
                        {t('account.signInMethods.link', 'Link')}
                      </Button>
                    )
                  }
                />
              )
            })}
            {other.map((identity) => (
              <SignInMethodRow
                key={identity.id}
                icon={<Building2 className="text-muted-foreground" />}
                title={otherName}
                lines={statusLines(identity)}
                action={unlinkButton(identity, otherName)}
              />
            ))}
          </ul>
        )}
      </CardContent>

      <StepUpDialog
        open={!!toLink}
        onOpenChange={(open) => !open && setToLink(null)}
        title={t('account.signInMethods.linkTitle', 'Link {provider}', {
          provider: toLink?.org_name ?? '',
        })}
        description={`${t('account.organizationSignIn.linkDesc', 'Next you sign in at {provider}, then come back here.', { provider: toLink?.display_name ?? '' })}${proofKind ? ` ${proofHint}` : ''}`}
        factor={proofKind === 'password' ? 'password' : 'totp'}
        submitLabel={t('account.signInMethods.link', 'Link')}
        onSubmit={confirmLink}
        errorMessage={proofError(
          t(
            'account.organizationSignIn.linkFailed',
            "Your organization's sign-in could not be linked. Try again."
          )
        )}
        notice={noProofNotice(() => setToLink(null))}
      />

      <StepUpDialog
        open={!!toUnlink}
        onOpenChange={(open) => !open && !isUnlinking && setToUnlink(null)}
        title={t('account.signInMethods.unlinkTitle', 'Unlink {provider}?', {
          provider: toUnlink?.name ?? '',
        })}
        description={`${t(
          'account.organizationSignIn.unlinkDesc',
          'You will sign in with your password again. If your organization requires single sign-on, link it again to keep access.'
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
