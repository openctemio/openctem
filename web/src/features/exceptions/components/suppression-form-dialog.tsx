'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

import { useCreateSuppression, useUpdateSuppression } from '../api/use-suppressions-api'
import { suppressionTypeLabel, type SuppressionRule, type SuppressionType } from '../types'

interface SuppressionFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** When set, the dialog edits this rule; otherwise it creates a new one. */
  rule?: SuppressionRule | null
  onSuccess?: () => void
}

const TYPE_OPTIONS: SuppressionType[] = ['false_positive', 'accepted_risk', 'wont_fix']

/** Every rule ends: 90 days by default, at most 365 days ahead (API rule). */
export const DEFAULT_RULE_DAYS = 90
export const MAX_RULE_DAYS = 365
const DAY_MS = 24 * 60 * 60 * 1000

/**
 * Why an end date cannot be used (`missing`, `past`, `tooLate`), or null
 * when it is fine. `local` is a datetime-local value.
 */
export function ruleEndProblem(
  local: string,
  now: Date = new Date()
): 'missing' | 'past' | 'tooLate' | null {
  const iso = toRfc3339(local)
  if (!iso) return 'missing'
  const at = new Date(iso).getTime()
  if (at <= now.getTime()) return 'past'
  if (at > now.getTime() + MAX_RULE_DAYS * DAY_MS) return 'tooLate'
  return null
}

/** Convert an <input type="datetime-local"> value to RFC3339, or null if blank. */
function toRfc3339(local: string): string | null {
  if (!local) return null
  const d = new Date(local)
  if (Number.isNaN(d.getTime())) return null
  return d.toISOString()
}

/** Convert an RFC3339 timestamp to a value the datetime-local input accepts. */
function toLocalInput(iso?: string | null): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function SuppressionFormDialog({
  open,
  onOpenChange,
  rule,
  onSuccess,
}: SuppressionFormDialogProps) {
  const { t } = useTranslation()
  const isEdit = Boolean(rule)

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [suppressionType, setSuppressionType] = useState<SuppressionType>('false_positive')
  const [toolName, setToolName] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [pathPattern, setPathPattern] = useState('')
  const [expiresAt, setExpiresAt] = useState('')

  const { trigger: triggerCreate, isMutating: isCreating } = useCreateSuppression()
  const { trigger: triggerUpdate, isMutating: isUpdating } = useUpdateSuppression(rule?.id ?? '')
  const isSubmitting = isCreating || isUpdating

  // Hydrate form when opening (reset for create, prefill for edit).
  useEffect(() => {
    if (!open) return
    setName(rule?.name ?? '')
    setDescription(rule?.description ?? '')
    setSuppressionType(rule?.suppression_type ?? 'false_positive')
    setToolName(rule?.tool_name ?? '')
    setRuleId(rule?.rule_id ?? '')
    setPathPattern(rule?.path_pattern ?? '')
    setExpiresAt(
      toLocalInput(
        rule?.expires_at ?? new Date(Date.now() + DEFAULT_RULE_DAYS * DAY_MS).toISOString()
      )
    )
  }, [open, rule])

  // Backend requires at least one of rule_id / path_pattern / asset_id.
  // The console exposes rule_id and path_pattern; require one of them.
  const hasCriteria = ruleId.trim() !== '' || pathPattern.trim() !== ''
  const endProblem = ruleEndProblem(expiresAt)
  const canSubmit = name.trim() !== '' && hasCriteria && endProblem === null && !isSubmitting

  const handleSubmit = async () => {
    if (!canSubmit) return
    const expires = toRfc3339(expiresAt)
    try {
      if (isEdit && rule) {
        await triggerUpdate({
          name: name.trim(),
          description: description.trim(),
          rule_id: ruleId.trim(),
          tool_name: toolName.trim(),
          path_pattern: pathPattern.trim(),
          expires_at: expires ?? undefined,
        })
        toast.success(t('exceptions.form.updated', 'Suppression rule updated'))
      } else {
        await triggerCreate({
          name: name.trim(),
          description: description.trim() || undefined,
          suppression_type: suppressionType,
          rule_id: ruleId.trim() || undefined,
          tool_name: toolName.trim() || undefined,
          path_pattern: pathPattern.trim() || undefined,
          expires_at: expires ?? undefined,
        })
        toast.success(t('exceptions.form.submitted', 'Suppression rule submitted for approval'))
      }
      onSuccess?.()
      onOpenChange(false)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          isEdit
            ? t('exceptions.form.updateFailed', 'Failed to update suppression rule')
            : t('exceptions.form.createFailed', 'Failed to create suppression rule')
        )
      )
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {isEdit
              ? t('exceptions.form.editTitle', 'Edit Suppression Rule')
              : t('exceptions.form.newTitle', 'New Suppression Rule')}
          </DialogTitle>
          <DialogDescription>
            {isEdit
              ? t(
                  'exceptions.form.editDescription',
                  'Update the matching criteria or expiry for this suppression rule.'
                )
              : t(
                  'exceptions.form.newDescription',
                  'Suppress false positives or accepted risks. New rules require approval before they take effect.'
                )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="grid gap-4 py-2">
            <div className="grid gap-2">
              <Label htmlFor="suppression-name">
                {t('exceptions.form.name', 'Name')} <span className="text-destructive">*</span>
              </Label>
              <Input
                id="suppression-name"
                placeholder={t(
                  'exceptions.form.namePlaceholder',
                  'e.g. Ignore test-fixture secrets'
                )}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={200}
              />
            </div>

            {!isEdit && (
              <div className="grid gap-2">
                <Label htmlFor="suppression-type">
                  {t('exceptions.form.type', 'Type')} <span className="text-destructive">*</span>
                </Label>
                <Select
                  value={suppressionType}
                  onValueChange={(v) => setSuppressionType(v as SuppressionType)}
                >
                  <SelectTrigger id="suppression-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TYPE_OPTIONS.map((type) => (
                      <SelectItem key={type} value={type}>
                        {suppressionTypeLabel(type, t)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="grid gap-2">
              <Label htmlFor="suppression-desc">
                {t('exceptions.form.description', 'Description')}
              </Label>
              <Textarea
                id="suppression-desc"
                placeholder={t(
                  'exceptions.form.descriptionPlaceholder',
                  'Why is this finding being suppressed?'
                )}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                maxLength={2000}
              />
            </div>

            <div className="rounded-lg border p-3 space-y-3">
              <p className="text-xs text-muted-foreground">
                {t(
                  'exceptions.form.criteriaHint',
                  'Matching criteria — provide a rule ID or a path pattern (at least one is required). Tool name further narrows the match.'
                )}
              </p>
              <div className="grid gap-2 sm:grid-cols-2">
                <div className="grid gap-2">
                  <Label htmlFor="suppression-tool">
                    {t('exceptions.form.toolName', 'Tool name')}
                  </Label>
                  <Input
                    id="suppression-tool"
                    placeholder="semgrep"
                    value={toolName}
                    onChange={(e) => setToolName(e.target.value)}
                    maxLength={100}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="suppression-rule-id">
                    {t('exceptions.form.ruleId', 'Rule ID')}
                  </Label>
                  <Input
                    id="suppression-rule-id"
                    placeholder="semgrep.sql-injection"
                    value={ruleId}
                    onChange={(e) => setRuleId(e.target.value)}
                    maxLength={200}
                  />
                </div>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="suppression-path">
                  {t('exceptions.form.pathPattern', 'Path pattern')}
                </Label>
                <Input
                  id="suppression-path"
                  placeholder="tests/**"
                  value={pathPattern}
                  onChange={(e) => setPathPattern(e.target.value)}
                  maxLength={500}
                />
              </div>
              {!hasCriteria && (name.trim() !== '' || toolName.trim() !== '') && (
                <p className="text-xs text-destructive">
                  {t(
                    'exceptions.form.criteriaRequired',
                    'Provide a rule ID or a path pattern so the rule can match findings.'
                  )}
                </p>
              )}
            </div>

            <div className="grid gap-2">
              <Label htmlFor="suppression-expires">{t('exceptions.form.endsAt', 'Ends')}</Label>
              <Input
                id="suppression-expires"
                type="datetime-local"
                required
                value={expiresAt}
                aria-invalid={endProblem !== null}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
              {endProblem ? (
                <p className="text-xs text-destructive" role="alert">
                  {endProblem === 'missing'
                    ? t('exceptions.form.endMissing', 'Choose when the rule ends.')
                    : endProblem === 'past'
                      ? t('exceptions.form.endPast', 'The end must be in the future.')
                      : t('exceptions.form.endTooLate', 'A rule ends within 365 days.')}
                </p>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {t(
                    'exceptions.form.endsHint',
                    'Every rule ends: 90 days by default, at most 365 days. To keep suppressing after that, submit a new rule for approval.'
                  )}
                </p>
              )}
            </div>
          </div>
        </DialogBody>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            {t('exceptions.form.cancel', 'Cancel')}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            {isSubmitting ? (
              <>
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
                {isEdit
                  ? t('exceptions.form.saving', 'Saving...')
                  : t('exceptions.form.creating', 'Creating...')}
              </>
            ) : isEdit ? (
              t('exceptions.form.save', 'Save Changes')
            ) : (
              t('exceptions.form.create', 'Create Rule')
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
