'use client'

/**
 * Where a CI trust configuration gets the provider's signing keys (api
 * RFC-051, "Pasted signing keys"): fetched from the provider, or pasted by an
 * administrator so the platform never contacts the provider. The pasted
 * document is public key material; the API refuses private keys.
 */

import { ChoiceGroup } from '@/components/ui/choice-group'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { RelativeTime } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import type { CIProvider, CITrustConfig } from '../types'
import { checkSigningKeys, type KeySource, type PastedKey } from '../lib/signing-keys'

type TFn = ReturnType<typeof useTranslation>['t']

/** Where to copy the keys from, per provider. */
function keysHelp(provider: CIProvider, t: TFn): string {
  switch (provider) {
    case 'gitlab':
      return t(
        'scans.ci.trust.signingKeys.helpGitlab',
        'Open https://<your GitLab>/oauth/discovery/keys and paste the whole document (all keys).'
      )
    case 'github':
      return t(
        'scans.ci.trust.signingKeys.helpGithub',
        'Open <issuer>/.well-known/jwks (https://token.actions.githubusercontent.com/.well-known/jwks for github.com) and paste the whole document (all keys).'
      )
    default:
      return t(
        'scans.ci.trust.signingKeys.helpOther',
        'Open the jwks_uri named in <issuer>/.well-known/openid-configuration and paste the whole document (all keys).'
      )
  }
}

/** "kid (alg), kid (alg)" for a key list. */
export function keyListText(keys: readonly { kid?: string; alg?: string }[]): string {
  return keys.map((k) => `${k.kid ?? ''} (${k.alg ?? ''})`).join(', ')
}

/**
 * The saved keys of a configuration: their ids and algorithms, when they were
 * pasted, and the key that verified the last admitted token.
 */
export function CITrustSigningKeysSummary({ config }: { config: CITrustConfig }) {
  const { t } = useTranslation()
  if (config.key_source !== 'pasted') return null
  const keys = config.signing_key_list ?? []
  return (
    <div
      className="space-y-0.5 text-xs text-muted-foreground"
      data-testid="ci-signing-keys-summary"
    >
      <p className="break-words">
        {t('scans.ci.trust.signingKeys.pastedKeys', 'Pasted signing keys')}
        {config.signing_keys_updated_at && (
          <>
            {' '}
            <RelativeTime date={config.signing_keys_updated_at} />
          </>
        )}
        {': '}
        <span className="font-mono">{keyListText(keys)}</span>
      </p>
      <p className="break-words">
        {config.last_key_id ? (
          <>
            {t('scans.ci.trust.signingKeys.lastUsedKey', 'Last used key')}{' '}
            <span className="font-mono">{config.last_key_id}</span>
          </>
        ) : (
          t('scans.ci.trust.signingKeys.noKeyUsed', 'No token verified with these keys yet')
        )}
      </p>
    </div>
  )
}

export function CITrustSigningKeys({
  provider,
  source,
  keys,
  onSourceChange,
  onKeysChange,
  saved,
}: {
  provider: CIProvider
  source: KeySource
  keys: string
  onSourceChange: (s: KeySource) => void
  onKeysChange: (v: string) => void
  /** The configuration as saved (its key list), when editing one. */
  saved?: CITrustConfig | null
}) {
  const { t } = useTranslation()
  const check = source === 'pasted' && keys.trim() ? checkSigningKeys(keys) : null
  const found: PastedKey[] = check?.ok ? check.keys : []
  // The saved keys are listed below; repeat the parsed ones only when they differ.
  const unchanged =
    saved?.key_source === 'pasted' &&
    keyListText(found) === keyListText(saved.signing_key_list ?? [])
  return (
    <section
      className="space-y-2"
      aria-labelledby="ci-signing-keys-heading"
      data-testid="ci-signing-keys"
    >
      <h3 id="ci-signing-keys-heading" className="text-sm font-medium">
        {t('scans.ci.trust.signingKeys.title', 'Signing keys')}
      </h3>
      <ChoiceGroup<KeySource>
        label={t('scans.ci.trust.signingKeys.title', 'Signing keys')}
        value={source}
        onValueChange={onSourceChange}
        data-testid="ci-key-source"
        options={[
          {
            value: 'fetch',
            label: t('scans.ci.trust.signingKeys.fetch', 'Fetch from the provider'),
            hint: t(
              'scans.ci.trust.signingKeys.fetchHint',
              'The platform fetches the keys from the provider, so it needs to reach it.'
            ),
          },
          {
            value: 'pasted',
            label: t('scans.ci.trust.signingKeys.pasted', 'Use keys I paste'),
            hint: t(
              'scans.ci.trust.signingKeys.pastedHint',
              'Job tokens are verified with these keys only; the provider is never contacted. Paste the keys again when the provider rotates them.'
            ),
          },
        ]}
      />
      {source === 'pasted' && (
        <div className="space-y-1">
          <Label htmlFor="ci-signing-keys-doc">
            {t('scans.ci.trust.signingKeys.document', 'Keys (JWKS document)')}
          </Label>
          <Textarea
            id="ci-signing-keys-doc"
            className="h-40 font-mono [field-sizing:fixed] break-all"
            spellCheck={false}
            autoComplete="off"
            placeholder='{"keys":[{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}]}'
            value={keys}
            onChange={(e) => onKeysChange(e.target.value)}
            aria-invalid={check ? !check.ok : undefined}
            aria-describedby="ci-signing-keys-help ci-signing-keys-status"
          />
          <p id="ci-signing-keys-help" className="text-xs text-muted-foreground">
            {keysHelp(provider, t)}
          </p>
          <div id="ci-signing-keys-status" aria-live="polite">
            {check && !check.ok ? (
              <p
                className="text-xs text-destructive"
                role="alert"
                data-testid="ci-signing-keys-error"
              >
                {t(check.problem.key, check.problem.fallback, check.problem.params)}
              </p>
            ) : found.length > 0 && !unchanged ? (
              <p
                className="break-words text-xs text-muted-foreground"
                data-testid="ci-signing-keys-found"
              >
                {t(
                  'scans.ci.trust.signingKeys.found',
                  '{count, plural, one {# key:} other {# keys:}}',
                  {
                    count: found.length,
                  }
                )}{' '}
                <span className="font-mono">{keyListText(found)}</span>
              </p>
            ) : null}
          </div>
          {saved && <CITrustSigningKeysSummary config={saved} />}
        </div>
      )}
    </section>
  )
}

/** Whether the dialog may save: pasted mode needs a valid document. */
export function signingKeysReady(source: KeySource, keys: string): boolean {
  return source === 'fetch' || checkSigningKeys(keys).ok
}
