'use client'

/**
 * One answer of the scope gate per target (RFC-054 §6.4, §6.5): allowed and
 * through what, or refused with the reason and the fixes the caller may take.
 * The scan dialog's live preview and a refused scan (`TARGET_OUT_OF_SCOPE`,
 * `details.refused[]`) render through the same rows, so a refusal looks the
 * same wherever it comes from.
 *
 * The fixes come from the server, already narrowed to what the caller may
 * do (an approver gets "Allow for 7 days", a member "Request access"). Each
 * button goes through the normal route: an entry the approver adds is
 * audited, needs step-up and may wait for approvals; nothing here grants
 * anything by itself.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { CheckCircle2, Loader2, ShieldAlert, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { VerifyDomainDialog } from '@/features/attack-surface/components/easm-verify-domain-dialog'
import { assetDetailHref, isLinkableAssetId } from '@/features/findings/lib/asset-link'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import {
  approveScopeTarget,
  invalidateScopeCache,
  setScopeTargetActive,
  updateScopeTarget,
} from '../api/use-scope-api'
import type { ApiScopeCheckResult, ApiScopeFix } from '../api/scope-api.types'
import {
  scopeErrorMessage,
  scopeFixLabel,
  scopeRefusalLabel,
  scopeRefusalMessage,
} from '../lib/scope-codes'
import { ScopeEntryDialog, type ScopeEntryDraft } from './scope-entry-dialog'

/** A refusal as `TARGET_OUT_OF_SCOPE` lists it in `details.refused[]`. */
export interface ScopeRefusal {
  target?: string
  code?: string
  message?: string
  rule?: { kind?: string; id?: string; pattern?: string }
  fixes?: ApiScopeFix[]
}

/**
 * The refused targets of an API error, when it is `TARGET_OUT_OF_SCOPE`
 * (or any error whose details carry `refused[]`); otherwise [].
 */
export function refusedFromError(err: unknown): ScopeRefusal[] {
  const details = (err as { details?: unknown } | null | undefined)?.details
  const refused = (details as { refused?: unknown } | null | undefined)?.refused
  if (!Array.isArray(refused)) return []
  return refused.filter(
    (r): r is ScopeRefusal =>
      !!r && typeof r === 'object' && typeof (r as ScopeRefusal).target === 'string'
  )
}

/** Where a link fix leads, or null for fixes that act in place. */
export function fixHref(fix: ApiScopeFix, rule?: ScopeRefusal['rule']): string | null {
  switch (fix.action) {
    case 'remove_exclusion':
      return '/scope?tab=exclusions'
    case 'review_asset':
      return rule?.kind === 'asset' && isLinkableAssetId(rule.id)
        ? assetDetailHref(rule.id)
        : '/attack-surface/review'
    case 'add_zone':
      return '/sensors?tab=zones'
    case 'raise_tier':
      return '/scope?tab=targets'
    default:
      return null
  }
}

/** Fixes with nothing to click: shown as a hint, not a button. */
const HINT_ONLY = new Set(['use_tenant_sensor', 'contact_support'])

interface ScopeFixButtonsProps {
  fixes: ApiScopeFix[]
  rule?: ScopeRefusal['rule']
  /** Called after a fix changed something (re-run the check). */
  onApplied?: () => void
  size?: 'sm' | 'xs'
}

export function ScopeFixButtons({ fixes, rule, onApplied, size = 'xs' }: ScopeFixButtonsProps) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<ScopeEntryDraft | null>(null)
  const [verifyDomain, setVerifyDomain] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  if (fixes.length === 0) return null

  const run = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key)
    try {
      await fn()
      await invalidateScopeCache()
      toast.success(done)
      onApplied?.()
    } catch (err) {
      toast.error(scopeErrorMessage(t, err, 'The change was not saved.'))
    } finally {
      setBusy(null)
    }
  }

  const onFix = (fix: ApiScopeFix, key: string) => {
    switch (fix.action) {
      case 'add_entry':
        setDraft({ target_type: fix.target_type, pattern: fix.pattern, duration: 'permanent' })
        return
      case 'allow_temporarily':
      case 'request_access':
        setDraft({
          target_type: fix.target_type,
          pattern: fix.pattern,
          duration: 'one_off',
          days: fix.days,
        })
        return
      case 'approve_entry':
        if (fix.id) void run(key, () => approveScopeTarget(fix.id!), 'Approval recorded')
        return
      case 'activate_entry':
        if (fix.id) void run(key, () => setScopeTargetActive(fix.id!, true), 'Entry activated')
        return
      case 'renew_entry':
        if (fix.id)
          void run(
            key,
            () => updateScopeTarget(fix.id!, { expires_in_days: fix.days ?? 7 }),
            'Entry renewed'
          )
        return
      case 'verify_domain':
        setVerifyDomain(fix.domain ?? fix.pattern ?? null)
        return
    }
  }

  const btn = size === 'xs' ? 'h-7 px-2 text-xs' : undefined

  return (
    <>
      <div className="flex flex-wrap items-center gap-1.5">
        {fixes.map((fix, i) => {
          const key = `${fix.action}-${i}`
          // Several fixes of one kind (add this IP, add the /24 around it):
          // name what each adds.
          const label =
            fix.pattern && fixes.filter((f) => f.action === fix.action).length > 1
              ? `${scopeFixLabel(t, fix)}: ${fix.pattern}`
              : scopeFixLabel(t, fix)
          if (HINT_ONLY.has(fix.action ?? '')) {
            return (
              <span key={key} className="text-xs text-muted-foreground">
                {label}
              </span>
            )
          }
          const href = safeInternalHref(fixHref(fix, rule))
          if (href) {
            return (
              <Button key={key} asChild size="sm" variant="outline" className={btn}>
                <Link href={href}>{label}</Link>
              </Button>
            )
          }
          return (
            <Button
              key={key}
              type="button"
              size="sm"
              variant={i === 0 ? 'default' : 'outline'}
              className={btn}
              disabled={busy !== null}
              onClick={() => onFix(fix, key)}
            >
              {busy === key && <Loader2 className="me-1 h-3 w-3 animate-spin" />}
              {label}
            </Button>
          )
        })}
      </div>
      <ScopeEntryDialog
        open={draft !== null}
        draft={draft ?? undefined}
        onOpenChange={(o) => !o && setDraft(null)}
        onCreated={() => onApplied?.()}
      />
      <VerifyDomainDialog
        domain={verifyDomain}
        onOpenChange={(o) => !o && setVerifyDomain(null)}
        onChanged={() => onApplied?.()}
      />
    </>
  )
}

/** Where an allowed target's authority comes from, in words. */
export function viaText(via: ApiScopeCheckResult['via']): string {
  if (!via) return 'Allowed'
  const proof = via.proof === 'verified' ? ', verified' : ''
  switch (via.kind) {
    case 'scope_target':
      return `Allowed by ${via.pattern ?? 'a scope entry'}${proof}`
    case 'seed':
      return `Allowed under the seed ${via.pattern ?? ''}${proof}`.trim()
    case 'verified_domain':
      return `Allowed under the verified domain ${via.pattern ?? ''}`.trim()
    case 'internal':
      return 'Private target: routed by its scan zone'
    default:
      return 'Allowed'
  }
}

interface ScopeCheckRowProps {
  /** A dry-run result, or a refusal from an error's details. */
  result: ApiScopeCheckResult | ScopeRefusal
  onApplied?: () => void
  className?: string
}

/** One target: allowed (and through what) or refused (why, and the fixes). */
export function ScopeCheckRow({ result, onApplied, className }: ScopeCheckRowProps) {
  const { t } = useTranslation()
  const allowed = 'allowed' in result && result.allowed === true
  const target = result.target ?? ''
  if (allowed) {
    const r = result as ApiScopeCheckResult
    return (
      <li className={cn('flex min-w-0 items-start gap-2 py-1.5 text-sm', className)}>
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-label="Allowed" />
        <div className="min-w-0">
          <span className="break-all font-mono text-xs">{target}</span>
          <p className="text-xs text-muted-foreground">
            {viaText(r.via)}
            {r.zone?.name ? ` · zone ${r.zone.name}` : ''}
          </p>
        </div>
      </li>
    )
  }
  const code = result.code
  return (
    <li className={cn('flex min-w-0 items-start gap-2 py-1.5 text-sm', className)}>
      {code === 'deny_list' || code === 'invalid_target' ? (
        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-label="Refused" />
      ) : (
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-label="Refused" />
      )}
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="break-all font-mono text-xs">{target}</span>
          <span className="text-xs font-medium">{scopeRefusalLabel(t, code)}</span>
        </div>
        <p className="text-xs text-muted-foreground">
          {scopeRefusalMessage(t, code, result.message)}
          {result.rule?.pattern ? ` (${result.rule.pattern})` : ''}
        </p>
        <ScopeFixButtons fixes={result.fixes ?? []} rule={result.rule} onApplied={onApplied} />
      </div>
    </li>
  )
}

interface ScopeRefusalPanelProps {
  refused: ScopeRefusal[]
  onApplied?: () => void
  className?: string
}

/**
 * A refused request (`TARGET_OUT_OF_SCOPE`) inside the dialog that sent it:
 * which targets, why, and the fixes, instead of one long toast.
 */
export function ScopeRefusalPanel({ refused, onApplied, className }: ScopeRefusalPanelProps) {
  const { t } = useTranslation()
  if (refused.length === 0) return null
  return (
    <div
      role="alert"
      className={cn('rounded-md border border-warning/40 bg-warning/5 p-3', className)}
    >
      <p className="text-sm font-medium">
        {refused.length === 1
          ? '1 target may not be scanned'
          : `${refused.length} targets may not be scanned`}
      </p>
      <p className="text-xs text-muted-foreground">{t('scope.error.TARGET_OUT_OF_SCOPE')}</p>
      <ScopeCheckList results={refused} onApplied={onApplied} className="mt-2" />
    </div>
  )
}

/** One line for a toast: "promo.net: Not in scope; old.acme.io: Marked not ours". */
export function scopeRefusalSummary(
  t: (key: string, fallback?: string) => string,
  refused: ScopeRefusal[],
  max = 3
): string {
  const parts = refused.slice(0, max).map((r) => `${r.target}: ${scopeRefusalLabel(t, r.code)}`)
  if (refused.length > max) parts.push(`and ${refused.length - max} more`)
  return parts.join('; ')
}

interface ScopeCheckListProps {
  results: (ApiScopeCheckResult | ScopeRefusal)[]
  onApplied?: () => void
  /** Show allowed targets too (default: refused only). */
  showAllowed?: boolean
  /** Rows shown before "and N more". */
  limit?: number
  className?: string
}

/** Refused targets first, each with its fixes; allowed ones after (optional). */
export function ScopeCheckList({
  results,
  onApplied,
  showAllowed = false,
  limit = 50,
  className,
}: ScopeCheckListProps) {
  const refused = results.filter((r) => !('allowed' in r && r.allowed))
  const allowed = showAllowed ? results.filter((r) => 'allowed' in r && r.allowed) : []
  const rows = [...refused, ...allowed]
  const shown = rows.slice(0, limit)
  if (rows.length === 0) return null
  return (
    <div className={className}>
      <ul className="divide-y" aria-label="Scope check per target">
        {shown.map((r, i) => (
          <ScopeCheckRow key={`${r.target}-${i}`} result={r} onApplied={onApplied} />
        ))}
      </ul>
      {rows.length > shown.length && (
        <p className="pt-1 text-xs text-muted-foreground">and {rows.length - shown.length} more</p>
      )}
    </div>
  )
}
