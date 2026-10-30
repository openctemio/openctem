'use client'

/**
 * Asks the signed-in person to confirm linking the provider account of a
 * social sign-in that was refused because its address has this account
 * (API docs: architecture/social-login-linking.md). The pending link is an
 * HttpOnly cookie the server actions read; the layout mounts this only when
 * that cookie exists. The API accepts the link only for the account it was
 * made for, from a session that signed in after it, once.
 */

import { useEffect, useState } from 'react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import {
  confirmPendingLinkAction,
  dismissPendingLinkAction,
  getPendingLinkAction,
  type PendingLink,
} from '@/features/auth/actions/social-auth-actions'
import { describeAuthCode } from '@/features/auth/lib/auth-error-codes'
import { requestStepUp, STEP_UP_REQUIRED_CODE } from '@/lib/api/step-up'

const PROVIDER_NAME: Record<PendingLink['provider'], string> = {
  google: 'Google',
  github: 'GitHub',
  microsoft: 'Microsoft',
}

export function PendingLinkPrompt() {
  const { t } = useTranslation()
  const [pending, setPending] = useState<PendingLink | null>(null)
  const [busy, setBusy] = useState(false)

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

  const confirm = async () => {
    setBusy(true)
    try {
      let res = await confirmPendingLinkAction()
      // The sign-in is older than the step-up window: confirm it is them,
      // then try once more.
      if (!res.success && res.code === STEP_UP_REQUIRED_CODE && (await requestStepUp())) {
        res = await confirmPendingLinkAction()
      }
      if (res.success) {
        toast.success(t('account.pendingLink.linked', undefined, { provider }))
      } else {
        toast.error(describeAuthCode(res.code, t) ?? t('account.signInMethods.linkFailed'))
      }
      setPending(null)
    } finally {
      setBusy(false)
    }
  }

  const dismiss = async () => {
    setPending(null)
    await dismissPendingLinkAction().catch(() => undefined)
  }

  return (
    <ConfirmDialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) void dismiss()
      }}
      title={t('account.pendingLink.title', undefined, { provider })}
      desc={t('account.pendingLink.desc', undefined, { provider, email: pending.email })}
      confirmText={t('account.pendingLink.confirm', undefined, { provider })}
      cancelBtnText={t('account.pendingLink.notNow')}
      handleConfirm={confirm}
      isLoading={busy}
    />
  )
}
