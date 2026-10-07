'use client'

/**
 * The scope gate's answer for one target as a compact pill (tables). The
 * answer comes from POST /scope/check (see `useScopeCheck`), never from
 * matching patterns in the browser.
 */

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { TonePill, type PillTone } from '@/features/shared'
import type { ApiScopeCheckResult } from '../api/scope-api.types'
import { scopeRefusalLabel, scopeRefusalMessage } from '../lib/scope-codes'
import { viaText } from './scope-check-results'

/** Platform and validity refusals are red; everything a tenant can fix is amber. */
export function refusalTone(code: string | undefined): PillTone {
  if (code === 'deny_list' || code === 'invalid_target') return 'destructive'
  if (code === 'rejected' || code === 'excluded') return 'muted'
  return 'warning'
}

export function ScopeCheckBadge({
  result,
  loading,
}: {
  result: ApiScopeCheckResult | undefined
  loading?: boolean
}) {
  const { t } = useTranslation()
  if (!result) {
    return loading ? (
      <Skeleton className="h-5 w-16 rounded-full" />
    ) : (
      <span className="text-muted-foreground">-</span>
    )
  }
  if (result.allowed) {
    return <TonePill tone="success" label="In scope" title={viaText(result.via)} state="allowed" />
  }
  return (
    <TonePill
      tone={refusalTone(result.code)}
      label={scopeRefusalLabel(t, result.code)}
      title={scopeRefusalMessage(t, result.code, result.message)}
      state={result.code}
    />
  )
}
