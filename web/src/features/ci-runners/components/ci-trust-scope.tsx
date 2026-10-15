'use client'

/**
 * The repository scope entries a CI trust adds ("Trust and add to scope").
 * Each pattern links to its scope entry and shows whether a verified
 * pipeline run under it has been seen (evidence, never required unless the
 * organization asks for proof in Scoping › Settings). A trust that does not
 * add its repositories (one saved before the option existed) offers it to
 * someone who may change scope.
 */

import { BadgeCheck, CircleDashed } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { useSaveTrustConfig } from '../api/use-ci'
import type { CIProvider, CITrustConfig, CITrustConfigRequest } from '../types'

/** Providers whose trusts add their repositories to scope. */
export function manageScopeSupported(provider: CIProvider | string | undefined): boolean {
  return provider === 'github' || provider === 'gitlab'
}

/** The trust as a change request with "Trust and add to scope" on. */
export function adoptScopeRequest(c: CITrustConfig): CITrustConfigRequest {
  return {
    name: c.name ?? '',
    provider: c.provider ?? '',
    issuer: c.issuer,
    audience: c.audience,
    default_branch: c.default_branch,
    rules: c.rules ?? {},
    enabled: c.enabled,
    manage_scope: true,
  } as CITrustConfigRequest
}

export function CITrustScopeEntries({
  config,
  onChanged,
}: {
  config: CITrustConfig
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { trigger: save, isMutating } = useSaveTrustConfig()
  if (!manageScopeSupported(config.provider)) return null
  const entries = config.scope_entries ?? []
  if (!config.manage_scope || !config.enabled) {
    const canAdopt =
      !config.manage_scope &&
      config.enabled &&
      can(Permission.CIWrite) &&
      can(Permission.ScopeWrite)
    return (
      <div
        className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground sm:col-span-2"
        data-testid="ci-trust-scope-off"
      >
        <span>
          {config.manage_scope
            ? t('scans.ci.trust.scope.disabled', 'Scope: none while the trust is disabled.')
            : t('scans.ci.trust.scope.off', 'Scope: not added (Trust and add to scope is off).')}
        </span>
        {canAdopt && config.id && (
          <Button
            size="sm"
            variant="outline"
            disabled={isMutating}
            onClick={() =>
              save({ id: config.id, body: adoptScopeRequest(config) })
                .then(() => {
                  toast.success(t('scans.ci.trust.scope.adopted', 'Repositories added to scope'))
                  onChanged?.()
                })
                .catch((e: unknown) => toast.error(getErrorMessage(e)))
            }
          >
            {t('scans.ci.trust.scope.adopt', 'Add these repositories to scope')}
          </Button>
        )}
      </div>
    )
  }
  if (entries.length === 0) return null
  return (
    <div className="space-y-1 sm:col-span-2" data-testid="ci-trust-scope">
      <p className="text-sm font-medium text-foreground">
        {t('scans.ci.trust.scope.title', 'In scope')}
      </p>
      <ul className="space-y-1">
        {entries.map((e) => (
          <li key={e.pattern} className="flex flex-wrap items-center gap-2 text-sm">
            <Link
              href={`/scope?search=${encodeURIComponent(e.pattern ?? '')}`}
              className="break-all font-mono text-xs underline-offset-2 hover:underline"
            >
              {e.pattern}
            </Link>
            {e.seen_at ? (
              <Badge
                variant="outline"
                className="gap-1"
                title={
                  // The repository is left out when it is outside the
                  // caller's data scope.
                  e.seen_repository
                    ? t(
                        'scans.ci.trust.scope.seenHint',
                        'A verified pipeline of {repository} ran under this trust on {at}.',
                        {
                          repository: e.seen_repository,
                          at: new Date(e.seen_at).toLocaleString(),
                        }
                      )
                    : t(
                        'scans.ci.trust.scope.seenHintNoRepo',
                        'A verified pipeline ran under this trust on {at}.',
                        { at: new Date(e.seen_at).toLocaleString() }
                      )
                }
              >
                <BadgeCheck className="size-3.5 text-success" aria-hidden />
                {t('scans.ci.trust.scope.seen', 'Seen in a verified pipeline')}
              </Badge>
            ) : (
              <Badge variant="secondary" className="gap-1">
                <CircleDashed className="size-3.5" aria-hidden />
                {t('scans.ci.trust.scope.notSeen', 'No verified pipeline yet')}
              </Badge>
            )}
            {!e.scope_target_id && e.removed_at && (
              <span className="text-xs text-muted-foreground">
                {t(
                  'scans.ci.trust.scope.removed',
                  'Removed from scope by a person on {at}; this trust will not add it again.',
                  { at: new Date(e.removed_at).toLocaleDateString() }
                )}
              </span>
            )}
            {!e.scope_target_id && !e.removed_at && (
              <span className="text-xs text-warning">
                {t(
                  'scans.ci.trust.scope.missing',
                  'Not in scope: the entry could not be added (see the audit log) or is waiting for approval.'
                )}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
