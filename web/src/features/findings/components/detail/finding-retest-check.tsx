'use client'

/**
 * Retest check section (design: research/221), next to the retest panel in
 * the finding drawer and on the finding page.
 *
 *   Retest check                                   [Edit] [Remove]
 *   Reflected XSS on /search · HTTP assertion · sha256:abcdef123456
 *   [T1 · active] [Calibrated] [Approved]
 *   Last verdict: Still vulnerable · 2 d ago
 *   How checks work ▸
 *
 * A finding without an automatic retest (pentest, manual, bug bounty, DAST
 * without a template) gets a check someone wrote: a nuclei template or an
 * HTTP assertion. "Retest now" and the proof of fix re-run it on a sensor.
 * Reading needs findings:read; attaching, editing and removing need
 * findings:retest_checks:write; approving an intrusive check needs scope
 * approval rights and a recent sign-in. The API is the authority; the
 * permission checks here only hide actions it would refuse.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import {
  CheckCircle2,
  Clock,
  FlaskConical,
  Loader2,
  Pencil,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import Link from '@/components/link'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { usePermissions } from '@/context/permission-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Permission } from '@/lib/permissions/constants'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import {
  shortDigest,
  useApproveRetestCheck,
  useFindingRetestCheck,
  useRemoveRetestCheck,
  type RetestCheck,
} from '../../api/use-finding-retest-check'
import { useFindingRetests, type FindingRetestWithCheck } from '../../api/use-finding-retests'
import { RetestCheckEditorDialog } from './retest-check-editor-dialog'
import { RetestCheckTierBadge } from './retest-check-tier-badge'
import { retestMeta } from './finding-retest'
import { SectionLoadError, isLoadFailure } from './section-load-error'

/** Where the organization's nuclei templates (and their sensor approval) are managed. */
export const TEMPLATE_LIBRARY_HREF = '/settings/scanning/templates'

const SUCCESS_SOFT = 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' // palette-ok: success accent — the theme has no semantic "success" token

interface FindingRetestCheckSectionProps {
  finding: { id: string }
  className?: string
}

export function FindingRetestCheckSection({ finding, className }: FindingRetestCheckSectionProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.FindingsRetestChecksWrite)
  const { data, error, isLoading, mutate } = useFindingRetestCheck(finding.id)
  const [editing, setEditing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const remove = useRemoveRetestCheck(finding.id)

  if (isLoading) return null
  if (error) {
    return isLoadFailure(error) ? (
      <SectionLoadError
        title={t('findings.detail.section.retestCheck', 'the retest check')}
        onRetry={() => void mutate()}
        className={className}
      />
    ) : null
  }
  const check = data?.check ?? null
  if (!check && !canWrite) return null

  const onRemove = async () => {
    try {
      await remove.trigger()
      toast.success(t('findings.retestCheck.removed', 'Retest check removed'))
      setRemoving(false)
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findings.retestCheck.removeFailed', 'Could not remove the check'))
      )
    }
  }

  return (
    <DetailSection
      title={t('findings.retestCheck.title', 'Retest check')}
      icon={FlaskConical}
      className={className}
      actions={
        canWrite ? (
          check ? (
            <>
              <Button
                variant="ghost"
                size="sm"
                className="h-7"
                onClick={() => setEditing(true)}
                aria-label={t('findings.retestCheck.edit', 'Edit check')}
              >
                <Pencil className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7"
                onClick={() => setRemoving(true)}
                aria-label={t('findings.retestCheck.remove', 'Remove check')}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </>
          ) : (
            <Button variant="outline" size="sm" className="h-7" onClick={() => setEditing(true)}>
              {t('findings.retestCheck.add', 'Add check')}
            </Button>
          )
        ) : undefined
      }
    >
      {check ? (
        <SavedCheck check={check} findingId={finding.id} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {t(
            'findings.retestCheck.empty',
            'No retest check. Attach a nuclei template or an HTTP assertion so Retest now can re-check this finding on a sensor.'
          )}
        </p>
      )}
      <HowChecksWork />
      <RetestCheckEditorDialog
        findingId={finding.id}
        open={editing}
        onOpenChange={setEditing}
        initial={check}
      />
      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title={t('findings.retestCheck.removeTitle', 'Remove the retest check?')}
        desc={t(
          'findings.retestCheck.removeDesc',
          'Retests of this finding stop using the check. The template stays in the template library.'
        )}
        confirmText={t('findings.retestCheck.removeConfirm', 'Remove')}
        destructive
        isLoading={remove.isMutating}
        handleConfirm={() => void onRemove()}
      />
    </DetailSection>
  )
}

function SavedCheck({ check, findingId }: { check: RetestCheck; findingId: string }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const approve = useApproveRetestCheck(findingId)
  const { data: retests } = useFindingRetests(findingId)
  const lastVerdict = (retests?.data as FindingRetestWithCheck[] | undefined)?.find(
    (r) => r.retest_check_id === check.id
  )
  const canApprove =
    check.approval.required && !check.approval.approved && hasPermission(Permission.ScopeApprove)

  const onApprove = async () => {
    try {
      await approve.trigger()
      toast.success(t('findings.retestCheck.approved', 'Retest check approved'))
    } catch (err) {
      if (err instanceof ApiClientError && err.statusCode === 409) {
        toast.error(
          t('findings.retestCheck.approveConflict', 'You cannot approve this version of the check'),
          {
            description: err.message
              ? toDisplayText(err.message, 300)
              : t(
                  'findings.retestCheck.approveConflictDesc',
                  'A second person must approve the version you wrote, or the check needs no approval.'
                ),
          }
        )
        return
      }
      toast.error(
        getErrorMessage(err, t('findings.retestCheck.approveFailed', 'Could not approve the check'))
      )
    }
  }

  const kindLabel =
    check.kind === 'nuclei'
      ? t('findings.retestCheck.kindNuclei', 'Nuclei template')
      : t('findings.retestCheck.kindAssertion', 'HTTP assertion')

  return (
    <div className="space-y-2" data-slot="retest-check-saved">
      <div className="min-w-0 text-sm">
        <span className="font-medium break-words">
          {toDisplayText(check.template_name, 200) ||
            t('findings.retestCheck.unnamed', 'Unnamed check')}
        </span>
        <span className="text-muted-foreground"> · {kindLabel}</span>
        {check.template_digest && (
          <span
            className="ms-1 font-mono text-xs text-muted-foreground"
            title={check.template_digest}
          >
            · {shortDigest(check.template_digest)}
          </span>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <RetestCheckTierBadge tier={check.tier} />
        {check.calibrated ? (
          <Badge variant="secondary" className={cn('font-medium', SUCCESS_SOFT)}>
            <CheckCircle2 className="h-3 w-3" />
            {t('findings.retestCheck.calibrated', 'Calibrated')}
          </Badge>
        ) : (
          <Badge variant="secondary" className="bg-muted font-medium text-muted-foreground">
            {t('findings.retestCheck.uncalibrated', 'Not calibrated yet')}
          </Badge>
        )}
        {check.approval.required &&
          (check.approval.approved ? (
            <Badge variant="secondary" className={cn('font-medium', SUCCESS_SOFT)}>
              <ShieldCheck className="h-3 w-3" />
              {t('findings.retestCheck.approvalDone', 'Approved')}
            </Badge>
          ) : (
            <Badge variant="secondary" className="bg-muted font-medium text-muted-foreground">
              <Clock className="h-3 w-3" />
              {t('findings.retestCheck.approvalPending', 'Awaiting approval')}
            </Badge>
          ))}
        {canApprove && (
          <Button
            variant="outline"
            size="sm"
            className="h-7"
            onClick={() => void onApprove()}
            disabled={approve.isMutating}
          >
            {approve.isMutating && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            {t('findings.retestCheck.approve', 'Approve')}
          </Button>
        )}
      </div>
      {check.tier_reason && (
        <p className="text-xs text-muted-foreground">{toDisplayText(check.tier_reason, 300)}</p>
      )}
      {!check.calibrated && (
        <p className="text-xs text-muted-foreground">
          {t(
            'findings.retestCheck.uncalibratedHelp',
            'Until the check has matched this finding once, a no-match reads "not reproduced", not fixed.'
          )}
        </p>
      )}
      {check.template_pending_sensor_approval && (
        <p className="text-xs text-muted-foreground">
          {t(
            'findings.retestCheck.pendingSensor',
            'The template is awaiting approval for your sensors.'
          )}{' '}
          {hasPermission(Permission.ScannerTemplatesRead) && (
            <Link
              href={TEMPLATE_LIBRARY_HREF}
              className="underline underline-offset-2 hover:text-foreground"
            >
              {t('findings.retestCheck.openLibrary', 'Open the template library')}
            </Link>
          )}
        </p>
      )}
      {lastVerdict && (
        <p className="text-xs text-muted-foreground">
          {t('findings.retestCheck.lastVerdict', 'Last verdict:')}{' '}
          <span className="font-medium text-foreground">{retestMeta(lastVerdict, t).label}</span>{' '}
          <RelativeTime
            date={lastVerdict.completed_at ?? lastVerdict.created_at}
            className="text-xs"
          />
        </p>
      )}
    </div>
  )
}

function HowChecksWork() {
  const { t } = useTranslation()
  return (
    <details className="text-xs text-muted-foreground">
      <summary className="cursor-pointer">
        {t('findings.retestCheck.howTitle', 'How checks work')}
      </summary>
      <ul className="mt-1.5 list-disc space-y-1 ps-4">
        <li>
          {t(
            'findings.retestCheck.howMatch',
            "The check runs against the finding's own target. A match means the issue is still there."
          )}
        </li>
        <li>
          {t(
            'findings.retestCheck.howCalibrate',
            'A check proves a fix only after it has matched this finding once (calibrated). Until then a no-match is "not reproduced", not fixed.'
          )}
        </li>
        <li>
          {t(
            'findings.retestCheck.howInconclusive',
            'A check that cannot load or run is inconclusive and never resolves the finding.'
          )}
        </li>
        <li>
          {t(
            'findings.retestCheck.howApproval',
            'Intrusive (T2) checks need approval by a second person with scope approval rights. Editing a check resets its approval and calibration.'
          )}
        </li>
        <li>
          {t('findings.retestCheck.howCredentials', 'Credentials are not allowed in a check.')}
        </li>
      </ul>
    </details>
  )
}
