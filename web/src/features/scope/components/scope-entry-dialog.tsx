'use client'

/**
 * Add a scope entry, or request one (RFC-054 §6.1, S6).
 *
 * - A scope approver adds a permanent entry or a one-off that expires. It is
 *   active at once when the organization needs no approval, otherwise it
 *   waits for the other approvers. The API asks for step-up
 *   re-authentication; the shared client opens that dialog and retries.
 * - Anyone else with scope:write requests a one-off for one name or address,
 *   with a reason. A request authorizes nothing until an approver approves it.
 *
 * The server decides everything shown here (status, approvals, refusals);
 * the dialog only explains it before the click.
 */

import { useEffect, useId, useMemo, useState } from 'react'
import { AlertTriangle, BadgeCheck, Info, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasPermission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { createScopeTarget, invalidateScopeCache, useScopeSettingsApi } from '../api/use-scope-api'
import type { ApiScopeTarget, ScopeTier } from '../api/scope-api.types'
import { extractRootDomain } from '@/features/assets/lib/domain-hierarchy'
import { VerifyDomainDialog } from '@/features/attack-surface/components/easm-verify-domain-dialog'
import {
  domainFor,
  useEASMVerifiedDomains,
} from '@/features/attack-surface/hooks/use-easm-verified-domains'
import { useLetters } from '@/features/scope-letters'
import { scopeErrorMessage } from '../lib/scope-codes'
import {
  coversText,
  durationAllowed,
  durationPolicy,
  expiryDateFor,
  formatDay,
  patternForCoverage,
  resolveDuration,
  TIER_HINT,
  TIER_LABEL,
  TIER_TOOLS,
  wildcardApex,
  type DurationChoice,
} from '../lib/scope-entry'
import { ScopeDurationField } from './scope-duration-field'
import {
  detectScopeKind,
  REQUESTABLE_TARGET_TYPES,
  SCOPE_KIND_LABEL,
  SCOPE_KIND_PLACEHOLDER,
  scopeKindOf,
  ScopeTargetTypeSelect,
  type ScopeKind,
} from './scope-target-type'

export type ScopeEntryDuration = 'permanent' | 'one_off'
export type DomainCoverage = 'name' | 'subdomains'

export interface ScopeEntryDraft {
  target_type?: string
  pattern?: string
  duration?: ScopeEntryDuration
  days?: number
  reason?: string
  /** The tier the probe needs (a tier_exceeds fix). */
  tier?: ScopeTier
}

interface ScopeEntryDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Prefill, for example from a refusal's fix ("Allow for 7 days"). */
  draft?: ScopeEntryDraft
  onCreated?: (entry: ApiScopeTarget) => void
}

/** A single name or address: what a member may request. */
export function isSingleTarget(type: string, pattern: string): boolean {
  const p = pattern.trim()
  if (!p || p.includes('*') || p.includes('/') || p.includes(' ')) return false
  if (type === 'ip_address') return !p.includes('-')
  return (REQUESTABLE_TARGET_TYPES as string[]).includes(type)
}

/**
 * Coverage default by depth (research/53 §4.3): a registrable domain covers
 * every name below it; a deeper host covers only itself.
 */
export function defaultCoverage(name: string): DomainCoverage {
  const host = wildcardApex(name) || name.trim().toLowerCase().replace(/\.$/, '')
  if (!host) return 'subdomains'
  return extractRootDomain(host) === host ? 'subdomains' : 'name'
}

/** Approvals the new entry needs before it authorizes anything. */
export function approvalsForNew(opts: {
  canApprove: boolean
  effective: number
  tier: ScopeTier
  /** The platform approval policy (RFC-054 §12.6); default required. */
  policy?: string
}): number {
  const base = opts.canApprove ? opts.effective : Math.max(1, opts.effective)
  const t2Floor = (opts.policy ?? 'required') === 'required'
  return opts.tier === 't2' && t2Floor ? Math.max(1, base) : base
}

export function ScopeEntryDialog({ open, onOpenChange, draft, onCreated }: ScopeEntryDialogProps) {
  const { t, locale } = useTranslation()
  const formId = useId()
  const canApprove = useHasPermission(Permission.ScopeApprove)
  const { data: settings, isLoading: settingsLoading } = useScopeSettingsApi(open)

  const oneOffPolicy = settings?.one_off_targets ?? 'admins_and_requests'
  const requestsAllowed = oneOffPolicy === 'admins_and_requests'

  // The kind is detected from what was typed; an override only when asked.
  const [override, setOverride] = useState<ScopeKind | null>(null)
  const [coverageTouched, setCoverageTouched] = useState(false)
  const [name, setName] = useState('')
  const [coverage, setCoverage] = useState<DomainCoverage>('subdomains')
  // null: the longest duration the policy allows, until the user picks one.
  const [durationPick, setDurationPick] = useState<DurationChoice | null>(null)
  const [tier, setTier] = useState<ScopeTier>('t1')
  const [tierTouched, setTierTouched] = useState(false)
  const [verifyDomain, setVerifyDomain] = useState<string | null>(null)
  const { domains: verifiedDomains, mutate: refreshDomains } = useEASMVerifiedDomains()
  const [reason, setReason] = useState('')
  const [description, setDescription] = useState('')
  // '' : the organization owns it; otherwise the letter that authorizes it.
  const [letterId, setLetterId] = useState('')
  const { data: letters } = useLetters()
  const usableLetters = useMemo(
    () => (letters ?? []).filter((l) => l.in_effect && !l.revoked_at),
    [letters]
  )
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Reset on open, from the draft.
  useEffect(() => {
    if (!open) return
    const pattern = draft?.pattern ?? ''
    const apex = wildcardApex(pattern)
    const draftKind = scopeKindOf(draft?.target_type)
    setOverride(draftKind && draftKind !== detectScopeKind(pattern) ? draftKind : null)
    setName(apex || pattern)
    setCoverage(apex ? 'subdomains' : pattern ? 'name' : 'subdomains')
    setCoverageTouched(!!pattern)
    setDurationPick(
      draft?.duration === 'permanent'
        ? { kind: 'permanent' }
        : draft?.duration === 'one_off' && draft.days
          ? { kind: 'days', days: draft.days }
          : null
    )
    setTier(draft?.tier ?? 't1')
    setTierTouched(!!draft?.tier)
    setReason(draft?.reason ?? '')
    setDescription('')
    setError(null)
  }, [open, draft])

  // The default tier follows the organization's setting once it loads.
  useEffect(() => {
    if (open && !tierTouched && settings?.default_max_tier)
      setTier(settings.default_max_tier as ScopeTier)
  }, [open, tierTouched, settings?.default_max_tier])

  const detected = detectScopeKind(name)
  const type: ScopeKind = override ?? detected ?? 'domain'
  const isDomain = type === 'domain'
  // A member's request is one name for a few days, never a wildcard (§6.1).
  const isRequest = !canApprove
  const effectiveCoverage: DomainCoverage = isRequest ? 'name' : coverage
  // A request keeps what was typed, so a wildcard is refused, not narrowed.
  const pattern = isDomain && !isRequest ? patternForCoverage(name, effectiveCoverage) : name.trim()
  // Intrusive (T2) entries follow the owner's limit, others the one-off one
  // (RFC-054 §12.4). Only what the policy allows can be picked; the default
  // is the longest allowed, never a forbidden value.
  const policy = durationPolicy(tier, settings, { isRequest })
  const duration = resolveDuration(durationPick, policy)
  const expiring = duration.kind === 'days'
  const expiryDays = duration.kind === 'days' ? duration.days : 0
  const needsReason = expiring || isRequest || tier === 't2'
  const approvals = approvalsForNew({
    canApprove,
    effective: settings?.effective_widening_approvals ?? 0,
    tier,
    policy: settings?.approval_policy?.mode,
  })

  const expiresOn = expiring ? formatDay(expiryDateFor(expiryDays), locale) : ''
  const summary = useMemo(() => {
    const parts: string[] = []
    if (name.trim()) parts.push(coversText({ pattern, target_type: type }))
    parts.push(
      expiring
        ? t('scope.entry.expiresOn', 'expires on {date}', { date: expiresOn })
        : t('scope.entry.permanent', 'permanent')
    )
    return parts.join(' · ')
  }, [name, pattern, type, expiring, expiresOn, t])

  // Domain proof (RFC-054 §8): intrusive probes always need a verified
  // domain; platform sensors need one when the operator says so.
  const proofRoot =
    isDomain && name.trim() ? extractRootDomain(wildcardApex(pattern) || pattern) : ''
  const proofMode = settings?.active_proof ?? 'off'
  const proofNeeded = !!proofRoot && (tier === 't2' || proofMode !== 'off')
  const proofRow = proofNeeded ? domainFor(proofRoot, verifiedDomains) : undefined
  const proofMissing = proofNeeded && proofRow?.status !== 'verified'

  const validate = (): string | null => {
    if (!name.trim()) return 'Enter a name or address.'
    if (!override && !detected)
      return 'This is not a domain, IP address, IP range, URL, repository or cloud account. Pick its kind, or check the spelling.'
    if (isRequest && !(REQUESTABLE_TARGET_TYPES as string[]).includes(type))
      return t('scope.error.REQUEST_MUST_BE_SINGLE')
    if (isRequest && !requestsAllowed) return t('scope.error.REQUEST_NOT_ALLOWED')
    if (isRequest && !isSingleTarget(type, pattern)) return t('scope.error.REQUEST_MUST_BE_SINGLE')
    if (!durationAllowed(duration, policy))
      return tier === 't2'
        ? t('scope.error.INTRUSIVE_NEEDS_EXPIRY')
        : t('scope.error.ONE_OFF_DISABLED')
    if (needsReason && !reason.trim()) return t('scope.error.REASON_REQUIRED')
    return null
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const problem = validate()
    if (problem) {
      setError(problem)
      return
    }
    setSaving(true)
    setError(null)
    try {
      const entry = await createScopeTarget({
        target_type: type,
        pattern,
        description: description.trim() || undefined,
        reason: reason.trim() || undefined,
        max_tier: tier,
        ...(expiring ? { expires_in_days: expiryDays } : {}),
        ...(letterId
          ? { authorization_source: 'authorization_letter' as const, letter_id: letterId }
          : {}),
      })
      await invalidateScopeCache()
      if (entry?.status === 'active') {
        toast.success(`${entry.pattern} is in scope`)
      } else if (isRequest) {
        toast.success('Request sent', {
          description: 'A scope approver will review it. It authorizes nothing until then.',
        })
      } else {
        const n = entry?.approvals_required ?? approvals
        toast.success(`${entry?.pattern ?? pattern} is waiting for approval`, {
          description: `It needs ${n} ${n === 1 ? 'approval' : 'approvals'} from another approver before scans may use it.`,
        })
      }
      // Overlap warnings ("a superset of api.example.com") ride on the entry.
      for (const w of (entry as { warnings?: string[] } | undefined)?.warnings ?? [])
        toast.warning(w)
      if (entry) onCreated?.(entry)
      onOpenChange(false)
    } catch (err) {
      setError(scopeErrorMessage(t, err, 'Could not save the scope entry.'))
    } finally {
      setSaving(false)
    }
  }

  const title = isRequest ? 'Request access' : 'Add to scope'
  const blocked = isRequest && !settingsLoading && !requestsAllowed

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {isRequest
              ? 'Ask a scope approver to allow one name or address for a few days. Scans may use it only after it is approved.'
              : 'Say what your organization may probe. Exclusions still win over every entry.'}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          {blocked ? (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription>{t('scope.error.REQUEST_NOT_ALLOWED')}</AlertDescription>
            </Alert>
          ) : (
            <form id={formId} onSubmit={submit} className="space-y-4">
              {error && (
                <div
                  role="alert"
                  className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor={`${formId}-name`}>What</Label>
                <Input
                  id={`${formId}-name`}
                  value={name}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={SCOPE_KIND_PLACEHOLDER[type]}
                  onChange={(e) => {
                    const v = e.target.value
                    const apex = wildcardApex(v)
                    // Typing "*.x" picks "x and every name below it".
                    if (apex && !isRequest) {
                      setName(apex)
                      setCoverage('subdomains')
                      setCoverageTouched(true)
                    } else {
                      setName(v)
                      if (!coverageTouched) setCoverage(defaultCoverage(v))
                    }
                    setError(null)
                  }}
                />
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  {override ? (
                    <>
                      <span>Kind:</span>
                      <ScopeTargetTypeSelect
                        value={override}
                        onValueChange={(v) => setOverride(v as ScopeKind)}
                        only={isRequest ? REQUESTABLE_TARGET_TYPES : undefined}
                        className="h-7 w-44 text-xs"
                        aria-label="Kind"
                      />
                      <button
                        type="button"
                        className="underline underline-offset-2 hover:text-foreground"
                        onClick={() => setOverride(null)}
                      >
                        Detect it
                      </button>
                    </>
                  ) : (
                    <>
                      <span aria-live="polite">
                        {name.trim()
                          ? detected
                            ? `Detected: ${SCOPE_KIND_LABEL[detected]}`
                            : 'Kind not recognised'
                          : 'A domain, IP address, IP range, URL, repository or cloud account.'}
                      </span>
                      {name.trim() && (
                        <button
                          type="button"
                          className="underline underline-offset-2 hover:text-foreground"
                          onClick={() => setOverride(detected ?? 'domain')}
                        >
                          {detected ? 'Change' : 'Pick the kind'}
                        </button>
                      )}
                    </>
                  )}
                </div>
              </div>

              {isDomain && !isRequest && (
                <fieldset className="space-y-2">
                  <legend className="text-sm font-medium">Covers</legend>
                  <RadioGroup
                    value={coverage}
                    onValueChange={(v) => {
                      setCoverage(v as DomainCoverage)
                      setCoverageTouched(true)
                    }}
                    className="gap-2"
                  >
                    <CoverageOption
                      value="subdomains"
                      title={`${name.trim() || 'example.com'} and every name below it`}
                      hint={`Pattern *.${name.trim() || 'example.com'}. Add an exclusion of exactly the domain to leave it out.`}
                    />
                    <CoverageOption
                      value="name"
                      title={`${name.trim() || 'example.com'} only`}
                      hint="Names below it stay out of scope."
                    />
                  </RadioGroup>
                </fieldset>
              )}

              <div className="space-y-2">
                <Label htmlFor={`${formId}-tier`}>
                  {t('scope.entry.tierLabel', 'Deepest probe allowed')}
                </Label>
                <Select
                  value={tier}
                  onValueChange={(v) => {
                    setTier(v as ScopeTier)
                    setTierTouched(true)
                    setError(null)
                  }}
                >
                  <SelectTrigger id={`${formId}-tier`} className="w-full sm:w-56">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(isRequest ? ['t0', 't1'] : ['t0', 't1', 't2']).map((k) => (
                      <SelectItem key={k} value={k}>
                        {TIER_LABEL[k]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {TIER_HINT[tier]}{' '}
                  {t('scope.entry.tierTools', 'Runs: {tools}.', { tools: TIER_TOOLS[tier] })}
                  {tier !== 't0' && ` ${t('scope.entry.tierBelow', 'Lower tiers are included.')}`}
                </p>
              </div>

              <ScopeDurationField
                policy={policy}
                value={duration}
                onChange={(c) => {
                  setDurationPick(c)
                  setError(null)
                }}
              />

              <div
                className="rounded-md border bg-muted/40 px-3 py-2 text-sm"
                aria-live="polite"
                data-testid="entry-outcome"
              >
                <p className="font-medium break-words">{summary}</p>
                <p className="text-muted-foreground">
                  {approvals > 0
                    ? isRequest
                      ? t(
                          'scope.entry.outcomeRequest',
                          'A scope approver reviews it. It authorizes nothing until approved.'
                        )
                      : approvals === 1
                        ? t(
                            'scope.entry.outcomeApproval1',
                            'Needs 1 approval from another approver; it authorizes nothing until then.'
                          )
                        : t(
                            'scope.entry.outcomeApprovalN',
                            'Needs {n} approvals from other approvers; it authorizes nothing until then.',
                            { n: approvals }
                          )
                    : t(
                        'scope.entry.outcomeNow',
                        'Takes effect at once. You may be asked to confirm your identity first.'
                      )}
                  {expiring &&
                    ` ${t('scope.entry.outcomeExpires', 'It stops on {date}.', { date: expiresOn })}`}
                </p>
                {proofMissing && (
                  <div className="mt-2 flex flex-wrap items-center gap-2 border-t pt-2">
                    <p className="min-w-0 flex-1 text-xs text-muted-foreground">
                      {tier === 't2'
                        ? t(
                            'scope.entry.proofT2',
                            'Intrusive (T2) probes also need proof that you control {domain}.',
                            { domain: proofRoot }
                          )
                        : proofMode === 'all'
                          ? t(
                              'scope.entry.proofAll',
                              'Scans also need proof that you control {domain}.',
                              { domain: proofRoot }
                            )
                          : t(
                              'scope.entry.proofPlatform',
                              'Platform sensors also need proof that you control {domain}; your own sensors need this entry only.',
                              { domain: proofRoot }
                            )}
                    </p>
                    {!isRequest && (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-7 px-2 text-xs"
                        onClick={() => setVerifyDomain(proofRoot)}
                      >
                        <BadgeCheck className="me-1 h-3.5 w-3.5" aria-hidden />
                        {t('scope.entry.verifyDomain', 'Verify domain')}
                      </Button>
                    )}
                  </div>
                )}
              </div>

              {usableLetters.length > 0 && (
                <div className="space-y-2">
                  <Label htmlFor={`${formId}-authority`}>Authorized by</Label>
                  <Select
                    value={letterId || 'ownership'}
                    onValueChange={(v) => setLetterId(v === 'ownership' ? '' : v)}
                  >
                    <SelectTrigger id={`${formId}-authority`} className="w-full sm:w-80">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ownership">Our organization owns it</SelectItem>
                      {usableLetters.map((l) => (
                        <SelectItem key={l.id} value={l.id}>
                          Letter: {l.title} (until {new Date(l.valid_until).toLocaleDateString()})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {letterId && (
                    <p className="text-xs text-muted-foreground">
                      The entry authorizes probes only while the letter is valid, and stops when it
                      expires or is revoked.
                    </p>
                  )}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor={`${formId}-reason`}>Reason{needsReason ? '' : ' (optional)'}</Label>
                <Textarea
                  id={`${formId}-reason`}
                  rows={2}
                  value={reason}
                  maxLength={1000}
                  placeholder="Why may this be probed? For example: our domain, registrar account 123; pentest ticket OPS-12."
                  onChange={(e) => {
                    setReason(e.target.value)
                    setError(null)
                  }}
                />
                <p className="text-xs text-muted-foreground">Kept in the audit log.</p>
              </div>

              {!isRequest && (
                <div className="space-y-2">
                  <Label htmlFor={`${formId}-desc`}>Description (optional)</Label>
                  <Input
                    id={`${formId}-desc`}
                    value={description}
                    maxLength={1000}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>
              )}
            </form>
          )}
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          {!blocked && (
            <Button type="submit" form={formId} disabled={saving || settingsLoading}>
              {saving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              {isRequest ? 'Send request' : 'Add to scope'}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
      <VerifyDomainDialog
        domain={verifyDomain}
        existing={proofRow}
        onOpenChange={(o) => !o && setVerifyDomain(null)}
        onChanged={() => void refreshDomains()}
      />
    </Dialog>
  )
}

function CoverageOption({
  value,
  title,
  hint,
  disabled,
}: {
  value: string
  title: string
  hint: string
  disabled?: boolean
}) {
  const id = useId()
  return (
    <label
      htmlFor={id}
      className={cn(
        'flex cursor-pointer items-start gap-3 rounded-md border p-3 has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-primary/5',
        disabled && 'cursor-not-allowed opacity-60'
      )}
    >
      <RadioGroupItem id={id} value={value} disabled={disabled} className="mt-0.5" />
      <span className="min-w-0">
        <span className="block break-words text-sm font-medium">{title}</span>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </label>
  )
}
