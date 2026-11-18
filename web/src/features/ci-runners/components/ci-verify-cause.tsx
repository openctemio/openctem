'use client'

/**
 * Why the platform could not check a CI token, as a cause and the next step
 * in plain words (api RFC-051). The server's text stays below as the detail.
 * The issuer case offers the token's issuer as a one-click fix.
 */

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { verifyCause } from '../lib/connect'

export function CIVerifyCause({
  message,
  issuer,
  onUseIssuer,
}: {
  message: string
  /** The issuer the configuration names. */
  issuer?: string
  /** Replace the configuration's issuer with the token's. */
  onUseIssuer?: (issuer: string) => void
}) {
  const { t } = useTranslation()
  const cause = verifyCause(message, issuer)
  const text: Record<typeof cause.kind, string> = {
    private_address: t(
      'scans.ci.cause.privateAddress',
      'The platform cannot reach your CI provider: its address is private and not allowed. The platform operator allows its address range with the server setting OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS.'
    ),
    unreachable: t(
      'scans.ci.cause.unreachable',
      'The platform could not read the signing keys from your CI provider. Check that its address is right and reachable from the platform.'
    ),
    issuer_mismatch:
      cause.kind === 'issuer_mismatch'
        ? t(
            'scans.ci.cause.issuerMismatch',
            'Address differs: tokens say {token}, this configuration says {configured}.',
            { token: cause.token, configured: cause.configured }
          )
        : '',
    audience: t(
      'scans.ci.cause.audience',
      'The token was made for another audience. Copy the pipeline snippet again: its id_tokens audience must be the one shown here.'
    ),
    expired: t(
      'scans.ci.cause.expired',
      'The token has expired. Take a new one from a running job.'
    ),
    signature: t(
      'scans.ci.cause.signature',
      'The token is not signed by a key of this provider. Check that the address is the provider that issued it.'
    ),
    other: t('scans.ci.cause.other', 'The token could not be checked.'),
  }
  return (
    <div className="space-y-1" data-testid="ci-verify-cause">
      <p className="font-medium">{text[cause.kind]}</p>
      {cause.kind === 'issuer_mismatch' && onUseIssuer && (
        <Button type="button" variant="outline" size="sm" onClick={() => onUseIssuer(cause.token)}>
          {t('scans.ci.cause.useIssuer', 'Use {issuer}', { issuer: cause.token })}
        </Button>
      )}
      <p className="break-all text-xs text-muted-foreground">{message}</p>
    </div>
  )
}
