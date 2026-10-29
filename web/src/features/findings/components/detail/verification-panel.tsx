'use client'

/**
 * Verification panel: how this finding can be verified, from the server's
 * verification plan (GET /findings/{id}/verification), the proof recorded so
 * far, and the verification checklist editor. The transition engine stays
 * the only authority on Resolved; this panel explains it.
 */

import { useState } from 'react'
import { useSWRConfig } from 'swr'
import { toast } from 'sonner'
import { CheckCircle2, ClipboardCheck, Loader2, ShieldCheck, Star, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { usePermissions } from '@/context/permission-provider'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { cn } from '@/lib/utils'
import { SectionLoadError, isLoadFailure } from './section-load-error'
import {
  findingVerificationKey,
  saveVerificationChecklist,
  useFindingVerificationPlan,
  useVerificationChecklist,
  verificationChecklistKey,
  type VerificationMethod,
  type VerificationPlan,
} from '../../api/use-finding-verification'
import { findingTransitionsKey } from '../../api/use-finding-transitions'

type Translate = ReturnType<typeof useTranslation>['t']

const METHOD_LABEL: Record<string, string> = {
  retest: 'Retest',
  covered_scan: 'Covered scan',
  safe_check: 'Reachability check',
  rotation_proof: 'Rotation proof',
  evidence_review: 'Evidence review',
}

const METHOD_HELP: Record<string, string> = {
  retest: 'Re-runs the check that found it against its target.',
  covered_scan:
    'Closes on its own when a full scan with the same tool covers the asset and no longer finds it.',
  safe_check: 'Checks that the target is still reachable. Advisory: it never proves a fix.',
  rotation_proof:
    'The credential was revoked at the provider and replaced. Record it in the checklist.',
  evidence_review: 'The verification checklist, signed off as the risk tier requires.',
}

const REASON: Record<string, string> = {
  status_not_eligible: 'Not retested in this status',
  secret_needs_rotation: 'A leaked secret is verified by rotating it, not by a re-check',
  check_cannot_run: 'The custom retest check cannot run',
  no_tool_rule: 'This tool has no per-finding retest for this rule',
  template_not_rerun: 'This template is not re-run by a retest',
  no_asset: 'The finding has no asset',
  asset_inactive: 'The asset is not active',
  asset_not_network_addressable: 'The asset has no network address',
  asset_no_address: 'The asset has no address',
  target_refused: 'The target may not be probed (scope or deny list)',
  no_sensor: 'No sensor of your organization can re-check it',
  no_check_sensor: 'No sensor of your organization can run custom retest checks',
  no_template_sensor:
    "No online sensor has the template release this finding was found with. Update the sensor's templates.",
  no_automatic_retest:
    'A person reported this finding, so nothing re-checks it automatically. Attach a retest check to retest it.',
  imported_no_retest: 'Imported from a tool that no sensor of your organization runs',
  version_evidence_missing: 'The software version this finding was matched on is no longer known',
  version_source_not_rescannable:
    'The version came from a package list or the operating system, which no network scan reads again',
  active_check_unavailable: 'No installed check for this CVE is known on an online sensor',
  not_eligible: 'Not eligible for a retest',
  absence_not_proof_for_secrets: 'A secret stays valid after it is removed from code',
  source_not_scanned: 'No scanner re-runs a finding reported by a person',
  coverage_auto_resolve_review: 'Automatic closing by scan is in review mode on this platform',
  coverage_auto_resolve_off: 'Automatic closing by scan is off on this platform',
  not_for_secrets: 'Reachability says nothing about a leaked secret',
  finding_closed: 'The finding is closed',
}

const REQUIREMENT: Record<string, string> = {
  second_person_or_retest:
    'Needs proof: a passing retest, or the checklist completed by another person than the one who resolves.',
  checklist_or_retest: 'Needs proof: a passing retest or the completed checklist.',
  note: 'A note is enough to resolve it.',
}

export function methodLabel(t: Translate, kind: string): string {
  return t(`findings.verification.method.${kind}`, METHOD_LABEL[kind] ?? kind)
}

export function methodReason(t: Translate, reason?: string): string {
  if (!reason) return ''
  return t(`findings.verification.reason.${reason}`, REASON[reason] ?? reason)
}

function MethodRow({ method, t }: { method: VerificationMethod; t: Translate }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      {method.available ? (
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" aria-hidden />
      ) : (
        <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
      )}
      <span className="min-w-0">
        <span className={cn('font-medium', !method.available && 'text-muted-foreground')}>
          {methodLabel(t, method.kind)}
        </span>
        {method.recommended && (
          <Badge variant="secondary" className="ms-2 text-xs">
            <Star className="me-1 h-3 w-3" aria-hidden />
            {t('findings.verification.recommended', 'Recommended')}
          </Badge>
        )}
        <span className="block text-xs text-muted-foreground">
          {method.available
            ? t(`findings.verification.help.${method.kind}`, METHOD_HELP[method.kind] ?? '')
            : methodReason(t, method.reason)}
        </span>
      </span>
      <span className="sr-only">
        {method.available
          ? t('findings.verification.available', 'available')
          : t('findings.verification.unavailable', 'not available')}
      </span>
    </li>
  )
}

function EvidenceSummary({ plan, t }: { plan: VerificationPlan; t: Translate }) {
  const { checklist, retest } = plan.evidence
  return (
    <div className="space-y-1 text-sm">
      {retest && (
        <p>
          {t('findings.verification.lastRetest', 'Last retest:')}{' '}
          <span className="font-medium">
            {t(`findings.verification.outcome.${retest.outcome}`, retest.outcome)}
          </span>
          {retest.completed_at && (
            <>
              {', '}
              <RelativeTime date={retest.completed_at} className="text-sm" />
            </>
          )}
          {!retest.fresh && (
            <span className="block text-xs text-muted-foreground">
              {t(
                'findings.verification.stale',
                'Older than the last time the finding was seen or reopened, so it does not count.'
              )}
            </span>
          )}
        </p>
      )}
      <p>
        {t('findings.verification.checklist', 'Checklist:')}{' '}
        <span className="font-medium">
          {t(
            `findings.verification.checklistState.${checklist.state}`,
            checklist.state === 'complete'
              ? 'Complete'
              : checklist.state === 'in_progress'
                ? 'In progress'
                : 'Not started'
          )}
        </span>
        {checklist.completed_at && (
          <>
            {', '}
            <RelativeTime date={checklist.completed_at} className="text-sm" />
          </>
        )}
      </p>
      {checklist.state === 'complete' && !checklist.fresh && (
        <p className="text-xs text-muted-foreground">
          {t(
            'findings.verification.stale',
            'Older than the last time the finding was seen or reopened, so it does not count.'
          )}
        </p>
      )}
      {checklist.completed_by_caller && plan.second_person_required && (
        <p className="text-xs text-warning">
          {t(
            'findings.verification.youCompleted',
            'You completed the checklist, so another person must resolve this finding.'
          )}
        </p>
      )}
    </div>
  )
}

interface VerificationPanelProps {
  findingId: string
  className?: string
}

export function VerificationPanel({ findingId, className }: VerificationPanelProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const { data: plan, error, mutate } = useFindingVerificationPlan(findingId)
  const [open, setOpen] = useState(false)

  // A refusal stays hidden (no oracle); a real failure must not read as "no verification".
  if (isLoadFailure(error)) {
    return (
      <SectionLoadError
        title={t('findings.verification.loadTitle', 'verification')}
        onRetry={() => void mutate()}
        className={className}
      />
    )
  }
  if (error || !plan || plan.external_workflow) return null
  const isOpen = plan.methods.some((m) => m.reason !== 'finding_closed')
  if (!isOpen) return null
  const canEdit = hasPermission('ctem:verification_checklists:write')
  const checklistMethod = plan.methods.find(
    (m) => (m.kind === 'evidence_review' || m.kind === 'rotation_proof') && m.available
  )

  return (
    <DetailSection
      title={t('findings.verification.title', 'Verification')}
      icon={ShieldCheck}
      className={className}
      actions={
        canEdit && checklistMethod ? (
          <Button variant="outline" size="sm" className="h-7" onClick={() => setOpen(true)}>
            <ClipboardCheck className="h-3.5 w-3.5" />
            {t('findings.verification.openChecklist', 'Checklist')}
          </Button>
        ) : undefined
      }
    >
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge variant="outline">
          {t(`findings.verification.tier.${plan.tier}`, `Tier: ${plan.tier}`)}
        </Badge>
        {plan.proof_present ? (
          <Badge variant="secondary">
            {t('findings.verification.proofPresent', 'Proof recorded')}
          </Badge>
        ) : null}
      </div>
      <p className="text-sm text-muted-foreground">
        {t(`findings.verification.requirement.${plan.requirement}`, REQUIREMENT[plan.requirement])}
      </p>
      <ul
        className="space-y-2"
        aria-label={t('findings.verification.methodsAria', 'Verification methods')}
      >
        {plan.methods.map((m) => (
          <MethodRow key={m.kind} method={m} t={t} />
        ))}
      </ul>
      <EvidenceSummary plan={plan} t={t} />
      {open && (
        <ChecklistDialog
          findingId={findingId}
          secret={plan.methods.some((m) => m.kind === 'rotation_proof')}
          onClose={() => setOpen(false)}
        />
      )}
    </DetailSection>
  )
}

const ITEMS = ['exposure_cleared', 'evidence_attached', 'register_updated'] as const
type Item = (typeof ITEMS)[number]

const ITEM_LABEL: Record<Item, string> = {
  exposure_cleared: 'The exposure is gone (patched, removed or blocked)',
  evidence_attached: 'Evidence is attached (screenshot, commit, ticket, scan)',
  register_updated: 'The risk register or ticket is updated',
}

const SECRET_ITEM_LABEL: Record<Item, string> = {
  exposure_cleared: 'The credential is revoked at the provider and replaced where it was used',
  evidence_attached: 'Evidence is attached (provider audit entry, vault version, ticket)',
  register_updated: 'Use of the credential since exposure was checked and recorded',
}

function ChecklistDialog({
  findingId,
  secret,
  onClose,
}: {
  findingId: string
  secret: boolean
  onClose: () => void
}) {
  const { t } = useTranslation()
  const { mutate } = useSWRConfig()
  const { data, isLoading } = useVerificationChecklist(findingId)
  const [draft, setDraft] = useState<Partial<Record<Item, boolean>> & { notes?: string }>({})
  const [saving, setSaving] = useState(false)

  const value = (k: Item) => draft[k] ?? data?.[k] ?? false
  const notes = draft.notes ?? data?.notes ?? ''
  const labels = secret ? SECRET_ITEM_LABEL : ITEM_LABEL

  const save = async () => {
    if (saving) return
    setSaving(true)
    try {
      const out = await saveVerificationChecklist(findingId, {
        exposure_cleared: value('exposure_cleared'),
        evidence_attached: value('evidence_attached'),
        register_updated: value('register_updated'),
        notes,
      })
      toast.success(
        out.is_complete
          ? t('findings.verification.savedComplete', 'Checklist complete')
          : t('findings.verification.saved', 'Checklist saved')
      )
      void mutate(verificationChecklistKey(findingId))
      void mutate(findingVerificationKey(findingId))
      void mutate(findingTransitionsKey(findingId))
      onClose()
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findings.verification.saveFailed', 'Could not save the checklist'))
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {secret
              ? t('findings.verification.rotationTitle', 'Rotation proof')
              : t('findings.verification.checklistTitle', 'Verification checklist')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findings.verification.checklistDesc',
              'Completing every item records you as the person who verified the fix. For a critical finding, another person then resolves it.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-label={t('common.loading', 'Loading')} />
          ) : (
            <>
              {ITEMS.map((k) => (
                <div key={k} className="flex items-start gap-2">
                  <Checkbox
                    id={`vc-${k}`}
                    checked={value(k)}
                    onCheckedChange={(c) => setDraft((d) => ({ ...d, [k]: c === true }))}
                  />
                  <Label htmlFor={`vc-${k}`} className="text-sm leading-snug font-normal">
                    {t(`findings.verification.item${secret ? 'Secret' : ''}.${k}`, labels[k])}
                  </Label>
                </div>
              ))}
              <div className="space-y-1.5">
                <Label htmlFor="vc-notes">
                  {t('findings.verification.notes', 'Notes and evidence links')}
                </Label>
                <Textarea
                  id="vc-notes"
                  value={notes}
                  maxLength={4000}
                  rows={4}
                  placeholder={
                    secret
                      ? t(
                          'findings.verification.notesSecretPlaceholder',
                          'Provider, key reference (last 4 characters only), revoked on, ticket. Never paste the secret.'
                        )
                      : t(
                          'findings.verification.notesPlaceholder',
                          'Commit, ticket, scan run or screenshot reference'
                        )
                  }
                  onChange={(e) => setDraft((d) => ({ ...d, notes: e.target.value }))}
                />
              </div>
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={() => void save()} disabled={saving || isLoading}>
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            {t('findings.verification.save', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
