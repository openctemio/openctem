'use client'

/**
 * Asks the signed-in person to confirm linking the provider account of a
 * social sign-in that was refused because its address has this account
 * (API docs: architecture/social-login-linking.md). The pending link is an
 * HttpOnly cookie the server actions read; the layout mounts this only when
 * that cookie exists. The API accepts the link only for the account it was
 * made for, from a session that signed in after it, once, and only with the
 * proof typed here: the authenticator code, else the password. The sign-in
 * that just happened does not count.
 */

import { useEffect, useState } from 'react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { StepUpDialog, stepUpProofErrorMessage, type StepUpProofInput } from '@/components/security'
import { useTranslation } from '@/context/i18n-provider'
import {
  confirmPendingLinkAction,
  dismissPendingLinkAction,
  getPendingLinkAction,
  type PendingLink,
} from '@/features/auth/actions/social-auth-actions'
import { describeAuthCode } from '@/features/auth/lib/auth-error-codes'

import { linkProofFrom, LinkProofRefused } from '../lib/link-proof'

const PROVIDER_NAME: Record<PendingLink['provider'], string> = {
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
}

export function PendingLinkPrompt() {
  const { t } = useTranslation()
  const [pending, setPending] = useState<PendingLink | null>(null)

  useEffect(() => {
    let alive = true
    getPendingLinkAction()
      .then((p) => {
        if (alive) setPending(p)
      })
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [])

  if (!pending) return null
  const provider = PROVIDER_NAME[pending.provider]

  const confirm = async (input: StepUpProofInput) => {
    const proof = linkProofFrom(input)
    if (!proof) return
    const res = await confirmPendingLinkAction(proof)
    if (res.success) {
      toast.success(t('account.pendingLink.linked', undefined, { provider }))
      setPending(null)
      return
    }
    // A missing or wrong proof keeps the pending link: ask again in place.
    if (res.code === 'LINK_PROOF_FAILED' || res.code === 'LINK_PROOF_REQUIRED') {
      throw new LinkProofRefused(res.code)
    }
    toast.error(describeAuthCode(res.code, t) ?? t('account.signInMethods.linkFailed'))
    setPending(null)
  }

  const dismiss = async () => {
    setPending(null)
    await dismissPendingLinkAction().catch(() => undefined)
  }

  const desc = t('account.pendingLink.desc', undefined, { provider, email: pending.email })
  const proofHint =
    pending.proof === 'password'
      ? t('account.signInMethods.proofPassword')
      : t('account.signInMethods.proofCode')

  return (
    <StepUpDialog
      open
      onOpenChange={(open) => {
        if (!open) void dismiss()
      }}
      title={t('account.pendingLink.title', undefined, { provider })}
      description={pending.proof ? `${desc} ${proofHint}` : desc}
      factor={pending.proof === 'password' ? 'password' : 'totp'}
      submitLabel={t('account.pendingLink.confirm', undefined, { provider })}
      onSubmit={confirm}
      errorMessage={(err) =>
        (err instanceof LinkProofRefused ? describeAuthCode(err.code, t) : undefined) ??
        stepUpProofErrorMessage(t, err)
      }
      notice={
        pending.proof
          ? undefined
          : {
              body: <p className="text-sm">{t('account.signInMethods.proofUnavailable')}</p>,
              actions: (
                <Button type="button" variant="outline" onClick={() => void dismiss()}>
                  {t('account.pendingLink.notNow')}
                </Button>
              ),
            }
      }
    />
  )
}
