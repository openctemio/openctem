'use client'

/**
 * MobilizationBriefCard — the CTEM Mobilization "engineering-grade work item"
 * surface on the finding Remediation tab. It captures the two things a
 * ticket needs beyond a description so the assignee can act without a
 * back-and-forth (https://ctem.org/docs/stages/ctem-mobilization):
 *
 *   - Definition of done: success criteria + how the fix is verified.
 *   - Acceptable fixes:    a preferred fix plus alternatives the assignee
 *                          may choose from.
 *
 * These ride the finding's remediation JSONB and are pushed into the linked
 * Jira / GitHub ticket body server-side. Edited via
 * PATCH /findings/{id}/remediation.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { mutate as globalMutate } from 'swr'
import { Target, ClipboardCheck, Wrench, ListChecks, Pencil, Save, X, Loader2 } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { DynamicListInput } from '@/components/ui/dynamic-list-input'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useUpdateFindingRemediation } from '../../api/use-finding-evidence'
import { useTranslation } from '@/context/i18n-provider'

export interface MobilizationBrief {
  successCriteria?: string
  verificationMethod?: string
  preferredFix?: string
  alternativeFixes?: string[]
}

interface MobilizationBriefCardProps {
  findingId: string | null
  brief: MobilizationBrief
  canWrite: boolean
}

export function MobilizationBriefCard({ findingId, brief, canWrite }: MobilizationBriefCardProps) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [successCriteria, setSuccessCriteria] = useState(brief.successCriteria ?? '')
  const [verificationMethod, setVerificationMethod] = useState(brief.verificationMethod ?? '')
  const [preferredFix, setPreferredFix] = useState(brief.preferredFix ?? '')
  const [alternativeFixes, setAlternativeFixes] = useState<string[]>(brief.alternativeFixes ?? [])

  const { trigger, isMutating } = useUpdateFindingRemediation(findingId)

  const hasContent =
    !!brief.successCriteria ||
    !!brief.verificationMethod ||
    !!brief.preferredFix ||
    (brief.alternativeFixes?.length ?? 0) > 0

  function startEdit() {
    setSuccessCriteria(brief.successCriteria ?? '')
    setVerificationMethod(brief.verificationMethod ?? '')
    setPreferredFix(brief.preferredFix ?? '')
    setAlternativeFixes(brief.alternativeFixes ?? [])
    setEditing(true)
  }

  async function handleSave() {
    try {
      await trigger({
        success_criteria: successCriteria.trim(),
        verification_method: verificationMethod.trim(),
        preferred_fix: preferredFix.trim(),
        alternative_fixes: alternativeFixes.map((a) => a.trim()).filter(Boolean),
      })
      toast.success(t('findings.mobilizationBrief.updated', 'Mobilization brief updated'))
      setEditing(false)
      if (findingId) {
        void globalMutate(`/api/v1/findings/${findingId}`)
      }
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('findings.mobilizationBrief.updateFailed', 'Failed to update mobilization brief')
        )
      )
    }
  }

  return (
    <div className="rounded-lg border bg-muted/30 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 font-semibold">
            <Target className="h-4 w-4" />
            {t('findings.mobilizationBrief.title', 'Definition of Done & Acceptable Fixes')}
          </h3>
          <p className="text-muted-foreground text-sm">
            {t(
              'findings.mobilizationBrief.subtitle',
              'What “done” means and which fixes are acceptable — carried into the linked ticket.'
            )}
          </p>
        </div>
        {canWrite && !editing && (
          <Button size="sm" variant="outline" onClick={startEdit}>
            <Pencil className="me-2 h-4 w-4" />
            {hasContent
              ? t('findings.mobilizationBrief.edit', 'Edit')
              : t('findings.mobilizationBrief.add', 'Add')}
          </Button>
        )}
      </div>

      {editing ? (
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="mob-success">
              {t(
                'findings.mobilizationBrief.successLabel',
                'Definition of done (success criteria)'
              )}
            </Label>
            <Textarea
              id="mob-success"
              value={successCriteria}
              onChange={(e) => setSuccessCriteria(e.target.value)}
              placeholder={t(
                'findings.mobilizationBrief.successPlaceholder',
                'e.g. Scanner reports 0 instances on main for 2 consecutive scans.'
              )}
              rows={2}
              disabled={isMutating}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="mob-verify">
              {t('findings.mobilizationBrief.verifyLabel', 'How we verify the fix')}
            </Label>
            <Textarea
              id="mob-verify"
              value={verificationMethod}
              onChange={(e) => setVerificationMethod(e.target.value)}
              placeholder={t(
                'findings.mobilizationBrief.verifyPlaceholder',
                'e.g. Re-run the auth scan; add a unit test covering the sink.'
              )}
              rows={2}
              disabled={isMutating}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="mob-preferred">
              {t('findings.mobilizationBrief.preferredLabel', 'Preferred fix')}
            </Label>
            <Textarea
              id="mob-preferred"
              value={preferredFix}
              onChange={(e) => setPreferredFix(e.target.value)}
              placeholder={t(
                'findings.mobilizationBrief.preferredPlaceholder',
                'The recommended way to remediate this finding.'
              )}
              rows={2}
              disabled={isMutating}
            />
          </div>

          <div className="space-y-1.5">
            <Label>
              {t('findings.mobilizationBrief.altLabel', 'Alternative acceptable fixes')}
            </Label>
            <DynamicListInput
              items={alternativeFixes}
              onChange={setAlternativeFixes}
              placeholder={t(
                'findings.mobilizationBrief.altPlaceholder',
                'Another acceptable remediation…'
              )}
              addLabel={t('findings.mobilizationBrief.altAdd', 'Add alternative')}
            />
          </div>

          <div className="flex items-center gap-2">
            <Button size="sm" onClick={handleSave} disabled={isMutating}>
              {isMutating ? (
                <Loader2 className="me-1.5 h-3.5 w-3.5 animate-spin" />
              ) : (
                <Save className="me-1.5 h-3.5 w-3.5" />
              )}
              {t('common.save', 'Save')}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setEditing(false)}
              disabled={isMutating}
            >
              <X className="me-1.5 h-3.5 w-3.5" />
              {t('common.cancel', 'Cancel')}
            </Button>
          </div>
        </div>
      ) : hasContent ? (
        <div className="space-y-4">
          {brief.successCriteria && (
            <BriefItem
              icon={<ClipboardCheck className="h-3.5 w-3.5" />}
              label={t('findings.mobilizationBrief.itemDone', 'Definition of done')}
            >
              <p className="text-sm whitespace-pre-wrap leading-relaxed">{brief.successCriteria}</p>
            </BriefItem>
          )}
          {brief.verificationMethod && (
            <BriefItem
              icon={<ClipboardCheck className="h-3.5 w-3.5" />}
              label={t('findings.mobilizationBrief.itemVerification', 'Verification')}
            >
              <p className="text-sm whitespace-pre-wrap leading-relaxed">
                {brief.verificationMethod}
              </p>
            </BriefItem>
          )}
          {brief.preferredFix && (
            <BriefItem
              icon={<Wrench className="h-3.5 w-3.5" />}
              label={t('findings.mobilizationBrief.preferredLabel', 'Preferred fix')}
            >
              <p className="text-sm whitespace-pre-wrap leading-relaxed">{brief.preferredFix}</p>
            </BriefItem>
          )}
          {(brief.alternativeFixes?.length ?? 0) > 0 && (
            <BriefItem
              icon={<ListChecks className="h-3.5 w-3.5" />}
              label={t('findings.mobilizationBrief.itemAlternatives', 'Alternative fixes')}
            >
              <ul className="list-disc space-y-1 ps-5 text-sm leading-relaxed">
                {brief.alternativeFixes!.map((alt, i) => (
                  <li key={i}>{alt}</li>
                ))}
              </ul>
            </BriefItem>
          )}
        </div>
      ) : (
        <div className="rounded-lg border border-dashed p-4 text-center">
          <p className="text-muted-foreground text-sm">
            {t(
              'findings.mobilizationBrief.empty',
              'No definition of done or acceptable fixes recorded yet.'
            )}
          </p>
          {canWrite && (
            <p className="text-muted-foreground text-xs mt-1">
              {t(
                'findings.mobilizationBrief.emptyHint',
                'Add them so the assignee knows exactly when this is fixed and how to fix it.'
              )}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

function BriefItem({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode
  label: string
  children: React.ReactNode
}) {
  return (
    <div>
      <div className="text-muted-foreground mb-1 flex items-center gap-1.5 text-xs font-medium">
        {icon}
        {label}
      </div>
      {children}
    </div>
  )
}
