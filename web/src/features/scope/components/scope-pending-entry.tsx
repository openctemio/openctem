'use client'

/**
 * A target refused because the entry that covers it waits for approval
 * (RFC-054 §6.5 entry_pending, §7): everything that still blocks it, each
 * with what the viewer may do about it.
 *
 * - Approval: who can approve (named for people who may see the members,
 *   otherwise counted). The requester never gets an Approve button: they may
 *   remind the approvers (rate limited by the API) or, as the only owner
 *   with nobody else to approve, approve it themselves with an
 *   authenticator code. Another approver gets Approve.
 * - Tier: the entry allows less than the scan probes at.
 * - Domain proof: the probe needs the domain verified first.
 *
 * The server decides each of these again when the action is taken; this
 * only shows what is left and the buttons that would not be refused.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { BadgeCheck, Check, Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { extractRootDomain } from '@/features/assets/lib/domain-hierarchy'
import { VerifyDomainDialog } from '@/features/attack-surface/components/easm-verify-domain-dialog'
import {
  domainFor,
  useEASMVerifiedDomains,
} from '@/features/attack-surface/hooks/use-easm-verified-domains'
import { useDisplayUser } from '@/hooks/use-display-user'
import { Permission, useHasPermission } from '@/lib/permissions'
import {
  approveScopeTarget,
  invalidateScopeCache,
  useScopeSettingsApi,
  useScopeTargetApi,
} from '../api/use-scope-api'
import type { ApiScopeTarget } from '../api/scope-api.types'
import { scopeErrorMessage } from '../lib/scope-codes'
import { canApproveEntry, TIER_LABEL, wildcardApex } from '../lib/scope-entry'
import { approversText, RemindButton } from './scope-approvals'
import { ScopeSelfApproveDialog } from './scope-self-approve-dialog'

const TIER_RANK: Record<string, number> = { t0: 0, t1: 1, t2: 2 }

export type PendingBlocker = 'approval' | 'tier' | 'proof'

/**
 * What still blocks a target covered only by `entry` once it is approved:
 * always the approval, the tier when the entry allows less than `probeTier`,
 * and domain proof when the probe needs it and the domain is not verified.
 */
export function pendingBlockers(opts: {
  entry: Pick<ApiScopeTarget, 'max_tier'>
  probeTier?: number
  proofNeeded: boolean
  proofVerified: boolean
}): PendingBlocker[] {
  const out: PendingBlocker[] = ['approval']
  if (opts.probeTier !== undefined && TIER_RANK[opts.entry.max_tier ?? 't1'] < opts.probeTier)
    out.push('tier')
  if (opts.proofNeeded && !opts.proofVerified) out.push('proof')
  return out
}

/** Whether a probe at `probeTier` through `sensorPreference` needs a verified domain. */
export function proofNeededFor(
  mode: string | undefined,
  probeTier: number | undefined,
  sensorPreference: string | undefined
): boolean {
  if ((probeTier ?? 1) >= 2) return true
  if (mode === 'all') return true
  return mode === 'platform_sensors' && sensorPreference !== 'tenant'
}

interface ScopePendingEntryProps {
  /** The pending entry's id (the refusal's rule.id). */
  entryId: string
  /** The probe tier the check ran at. */
  probeTier?: number
  sensorPreference?: string
  onApplied?: () => void
}

export function ScopePendingEntry({
  entryId,
  probeTier,
  sensorPreference,
  onApplied,
}: ScopePendingEntryProps) {
  const { t } = useTranslation()
  const user = useDisplayUser()
  const mayApprove = useHasPermission(Permission.ScopeApprove)
  const mayWrite = useHasPermission(Permission.ScopeWrite)
  const { data: entry } = useScopeTargetApi(entryId)
  const { data: settings } = useScopeSettingsApi()
  const { domains, mutate: refreshDomains } = useEASMVerifiedDomains()
  const [busy, setBusy] = useState(false)
  const [selfApprove, setSelfApprove] = useState<ApiScopeTarget | null>(null)
  const [verify, setVerify] = useState<string | null>(null)

  if (!entry || entry.status !== 'pending') return null

  const mine = !!user?.id && entry.created_by?.id === user.id
  const canApproveIt = mayApprove && canApproveEntry(entry, user?.id)
  const isDomain = entry.target_type === 'domain' || entry.target_type === 'subdomain'
  const root = isDomain
    ? extractRootDomain(wildcardApex(entry.pattern ?? '') || (entry.pattern ?? ''))
    : ''
  const proofNeeded = !!root && proofNeededFor(settings?.active_proof, probeTier, sensorPreference)
  const proofRow = root ? domainFor(root, domains) : undefined
  const blockers = pendingBlockers({
    entry,
    probeTier,
    proofNeeded,
    proofVerified: proofRow?.status === 'verified',
  })

  const approve = async () => {
    setBusy(true)
    try {
      await approveScopeTarget(entry.id ?? '')
      await invalidateScopeCache()
      toast.success(t('scope.pending.approved', 'Approval recorded'))
      onApplied?.()
    } catch (err) {
      toast.error(
        scopeErrorMessage(t, err, t('scope.pending.notSaved', 'The change was not saved.'))
      )
    } finally {
      setBusy(false)
    }
  }

  const probeKey = `t${probeTier ?? 1}`
  const entryKey = entry.max_tier ?? 't1'
  const probeLabel = t(`scope.tier.label.${probeKey}`, TIER_LABEL[probeKey] ?? '')
  const entryLabel = t(`scope.tier.label.${entryKey}`, TIER_LABEL[entryKey] ?? '')

  return (
    <div className="space-y-1.5 rounded-md border bg-muted/30 p-2" data-testid="pending-entry">
      <p className="text-xs font-medium">
        {blockers.length === 1
          ? t('scope.pending.left1', 'One thing left before it can be scanned:')
          : t('scope.pending.leftN', '{n} things left before it can be scanned:', {
              n: blockers.length,
            })}
      </p>
      <ol className="list-decimal space-y-2 ps-4 text-xs">
        <li className="space-y-1">
          <p>
            {mine
              ? t(
                  'scope.pending.mine',
                  'You asked for {pattern}, so another approver must approve it.',
                  { pattern: entry.pattern ?? '' }
                )
              : t('scope.pending.waits', '{pattern} is waiting for approval.', {
                  pattern: entry.pattern ?? '',
                })}{' '}
            <span className="text-muted-foreground" data-testid="pending-approvers">
              {approversText(entry, t)}
            </span>
          </p>
          <div className="flex flex-wrap items-center gap-1.5">
            {canApproveIt && (
              <Button
                type="button"
                size="sm"
                className="h-7 px-2 text-xs"
                disabled={busy}
                onClick={() => void approve()}
              >
                {busy ? (
                  <Loader2 className="me-1 h-3 w-3 animate-spin" />
                ) : (
                  <Check className="me-1 h-3 w-3" />
                )}
                {t('scope.fix.approve_entry', 'Approve the entry')}
              </Button>
            )}
            {!canApproveIt && mayWrite && <RemindButton entry={entry} />}
            {entry.approval?.self_approval_available && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs"
                onClick={() => setSelfApprove(entry)}
              >
                <ShieldCheck className="me-1 h-3 w-3" />
                {t('scope.pending.selfApprove', 'Approve as the only owner')}
              </Button>
            )}
            <Link
              href="/scope?tab=approvals"
              className="text-muted-foreground underline underline-offset-2 hover:text-foreground"
            >
              {t('scope.pending.openApprovals', 'Open approvals')}
            </Link>
          </div>
        </li>
        {blockers.includes('tier') && (
          <li className="space-y-1">
            <p>
              {t(
                'scope.pending.tier',
                'This scan probes at {probe}; the entry allows {entry}. Raise the entry tier.',
                { probe: probeLabel, entry: entryLabel }
              )}
            </p>
            {mayApprove && (
              <Link
                href="/scope?tab=in"
                className="text-muted-foreground underline underline-offset-2 hover:text-foreground"
              >
                {t('scope.pending.changeTier', 'Change the tier')}
              </Link>
            )}
          </li>
        )}
        {blockers.includes('proof') && (
          <li className="space-y-1">
            <p>
              {t('scope.pending.proof', 'Prove that your organization controls {domain}.', {
                domain: root,
              })}
            </p>
            {mayApprove ? (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs"
                onClick={() => setVerify(root)}
              >
                <BadgeCheck className="me-1 h-3 w-3" />
                {t('scope.pending.verifyDomain', 'Verify domain')}
              </Button>
            ) : (
              <p className="text-muted-foreground">
                {t('scope.pending.proofAsk', 'A scope approver can verify it.')}
              </p>
            )}
          </li>
        )}
      </ol>
      {selfApprove && (
        <ScopeSelfApproveDialog
          entry={selfApprove}
          onOpenChange={() => {
            setSelfApprove(null)
            onApplied?.()
          }}
        />
      )}
      <VerifyDomainDialog
        domain={verify}
        existing={proofRow}
        onOpenChange={(o) => !o && setVerify(null)}
        onChanged={() => {
          void refreshDomains()
          onApplied?.()
        }}
      />
    </div>
  )
}
