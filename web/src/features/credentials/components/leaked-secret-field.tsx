'use client'

import * as React from 'react'
import { AlertTriangle, Check, Copy, Eye, EyeOff, Fingerprint, Key, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { useRevealCredentialApi } from '../api/use-credentials-api'

export interface LeakedSecretFieldProps {
  /** The credential (credential_leaked exposure) id. */
  credentialId: string
  /** Whether a secret is stored at all. */
  hasSecret: boolean
  /** Display-safe mask from the API (`secret_masked`). */
  masked?: string
  /** Keyed fingerprint from the API (`secret_fingerprint`). */
  fingerprint?: string
  label?: string
  showWarning?: boolean
  className?: string
}

/**
 * Shows a leaked credential's secret the way the API serves it: masked, with a
 * keyed fingerprint. The plaintext is fetched only when a user holding
 * findings:credentials:reveal presses Reveal; every reveal is recorded in the
 * audit log by the server. The plaintext lives only in this component's state
 * and is dropped on Hide or when another credential is shown.
 */
export function LeakedSecretField({
  credentialId,
  hasSecret,
  masked,
  fingerprint,
  label,
  showWarning = true,
  className,
}: LeakedSecretFieldProps) {
  const { t } = useTranslation()
  const heading = label ?? t('credentials.secret.label', 'Leaked secret')
  const canReveal = useHasPermission(Permission.CredentialsReveal)
  const { trigger, isMutating } = useRevealCredentialApi(credentialId)
  const [plaintext, setPlaintext] = React.useState<string | null>(null)
  const [isCopied, setIsCopied] = React.useState(false)

  // Never carry one credential's plaintext over to another.
  React.useEffect(() => {
    setPlaintext(null)
    setIsCopied(false)
  }, [credentialId])

  if (!hasSecret) {
    return (
      <div className={cn('rounded-xl border p-4 bg-card', className)}>
        <div className="flex items-center gap-2 mb-3">
          <Key className="h-4 w-4 text-muted-foreground" />
          <h4 className="text-sm font-medium">{heading}</h4>
        </div>
        <p className="text-sm text-muted-foreground italic">
          {t('credentials.secret.none', 'No secret value stored')}
        </p>
      </div>
    )
  }

  const handleReveal = async () => {
    try {
      const res = await trigger()
      if (!res?.secret_value) throw new Error('No secret returned')
      setPlaintext(res.secret_value)
      toast.info(
        t(
          'credentials.secret.revealed',
          'Secret revealed. This access is recorded in the audit log.'
        )
      )
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('credentials.secret.revealFailed', 'Failed to reveal the secret'))
      )
    }
  }

  const handleCopy = async () => {
    if (!plaintext) return
    const ok = await copyToClipboard(plaintext)
    if (!ok) {
      toast.error(t('credentials.secret.copyFailed', 'Failed to copy to clipboard'))
      return
    }
    setIsCopied(true)
    toast.success(t('credentials.secret.copied', 'Secret copied to clipboard'))
    setTimeout(() => setIsCopied(false), 2000)
  }

  const handleCopyFingerprint = async () => {
    if (fingerprint && (await copyToClipboard(fingerprint)))
      toast.success(t('credentials.secret.fingerprintCopied', 'Fingerprint copied'))
  }

  const revealed = plaintext !== null

  return (
    <div className={cn('rounded-xl border p-4 bg-card', className)}>
      <div className="flex items-center gap-2 mb-3">
        <Key className="h-4 w-4 text-warning" />
        <h4 className="text-sm font-medium">{heading}</h4>
      </div>

      {showWarning && (
        <div className="flex items-start gap-2 p-2 mb-3 rounded-lg bg-warning/10 border border-warning/30">
          <AlertTriangle className="h-4 w-4 text-warning mt-0.5 shrink-0" />
          <p className="text-xs text-warning">
            {t(
              'credentials.secret.warning',
              'This is sensitive data. Handle with care and rotate if compromised.'
            )}
          </p>
        </div>
      )}

      <div className="flex items-center gap-2">
        <Input
          type="text"
          value={revealed ? plaintext : masked || '********'}
          readOnly
          aria-label={
            revealed
              ? t('credentials.secret.valueAria', 'Secret value')
              : t('credentials.secret.maskedAria', 'Masked secret value')
          }
          data-testid="leaked-secret-value"
          className={cn('font-mono text-sm flex-1', !revealed && 'tracking-wider')}
        />
        {canReveal &&
          (revealed ? (
            <>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={handleCopy}
                aria-label={
                  isCopied
                    ? t('credentials.secret.copiedAria', 'Copied to clipboard')
                    : t('credentials.secret.copyAria', 'Copy secret')
                }
              >
                {isCopied ? (
                  <Check className="h-4 w-4 text-success" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => setPlaintext(null)}>
                <EyeOff className="me-1 h-4 w-4" />
                {t('credentials.secret.hide', 'Hide')}
              </Button>
            </>
          ) : (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleReveal}
              disabled={isMutating}
            >
              {isMutating ? (
                <Loader2 className="me-1 h-4 w-4 animate-spin" />
              ) : (
                <Eye className="me-1 h-4 w-4" />
              )}
              {t('credentials.secret.reveal', 'Reveal')}
            </Button>
          ))}
      </div>

      {fingerprint && (
        <button
          type="button"
          onClick={handleCopyFingerprint}
          className="mt-2 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
          title={t(
            'credentials.secret.fingerprintHint',
            'Same fingerprint = the same secret leaked again. Click to copy.'
          )}
        >
          <Fingerprint className="h-3 w-3" />
          <span className="font-mono">{fingerprint}</span>
        </button>
      )}
      {!canReveal && (
        <p className="mt-2 text-xs text-muted-foreground">
          {t(
            'credentials.secret.needsPermission',
            'Revealing the secret requires the Reveal Credential Secrets permission.'
          )}
        </p>
      )}
    </div>
  )
}
