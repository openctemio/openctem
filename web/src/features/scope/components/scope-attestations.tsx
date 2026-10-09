'use client'

/**
 * Keep intrusive (T2) entries (RFC-054 §12.5): long and permanent T2 entries
 * are confirmed periodically. An entry whose confirmation is due shows here
 * with the day it falls back to non-intrusive (T1); one click keeps it. The
 * entry is never removed by the fallback.
 */

import { useMemo, useState } from 'react'
import { Loader2, ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { RelativeTime, TonePill } from '@/features/shared'
import { Permission, useHasPermission } from '@/lib/permissions'
import { attestScopeTarget, invalidateScopeCache, useScopeTargetsApi } from '../api/use-scope-api'
import type { ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { coversText } from '../lib/scope-entry'

/** Active T2 entries whose confirmation was requested. */
export function attestationsDue(entries: ApiScopeTarget[]): ApiScopeTarget[] {
  return entries.filter(
    (e) => e.max_tier === 't2' && e.status === 'active' && !!e.attestation?.requested_at
  )
}

export function usePendingAttestations() {
  const active = useScopeTargetsApi({ status: 'active', per_page: 100 })
  const due = useMemo(() => attestationsDue(active.data?.data ?? []), [active.data])
  return { due, isLoading: active.isLoading }
}

export function ScopeAttestations() {
  const { t } = useTranslation()
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const { due } = usePendingAttestations()
  const [busy, setBusy] = useState<string | null>(null)

  if (due.length === 0) return null

  const keep = async (e: ApiScopeTarget) => {
    setBusy(e.id ?? '')
    try {
      await attestScopeTarget(e.id ?? '')
      await invalidateScopeCache()
      toast.success(`${e.pattern} keeps intrusive (T2) probes`)
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'Could not confirm the entry.'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="space-y-3" aria-label="Intrusive entries to confirm">
      <h3 className="text-sm font-medium">Confirm intrusive (T2) entries</h3>
      <ul className="space-y-3">
        {due.map((e) => (
          <li key={e.id} className="space-y-2 rounded-lg border border-warning/40 p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
              <div className="min-w-0 flex-1 space-y-1 break-words">
                <div className="flex flex-wrap items-center gap-2">
                  <TonePill tone="warning" label="Keep T2?" />
                  <code className="break-all text-sm font-medium">{e.pattern}</code>
                </div>
                <p className="text-sm text-muted-foreground">
                  Covers {coversText(e)}. {e.expires_at ? 'Expires later' : 'Permanent'}.
                </p>
                {e.reason && <p className="text-sm">&ldquo;{e.reason}&rdquo;</p>}
                {e.attestation?.downgrade_at && (
                  <p className="text-xs text-muted-foreground">
                    Without a confirmation it falls back to non-intrusive (T1){' '}
                    <RelativeTime date={e.attestation.downgrade_at} />. It is not removed.
                  </p>
                )}
              </div>
              {canApprove ? (
                <Button
                  size="sm"
                  className="shrink-0"
                  disabled={busy === e.id}
                  onClick={() => void keep(e)}
                >
                  {busy === e.id ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <ShieldAlert className="h-4 w-4" />
                  )}
                  Keep T2
                </Button>
              ) : (
                <p className="shrink-0 text-xs text-muted-foreground sm:max-w-56 sm:text-end">
                  A scope approver confirms this.
                </p>
              )}
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
