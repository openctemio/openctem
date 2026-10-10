'use client'

import { useEffect, useMemo, useState } from 'react'
import { ArrowDown, ArrowUp, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  DEPENDENCY_SCOPES,
  MAX_LICENSE_RULES,
  updateLicensePolicy,
  validateRuleMatch,
  type LicenseAction,
  type LicensePolicy,
  type LicenseRule,
} from '../api'

export interface LicensePolicyFormStatus {
  dirty: boolean
  submitting: boolean
}

function normalize(p: LicensePolicy): Required<LicensePolicy> {
  return {
    enabled: p.enabled ?? false,
    default: p.default ?? 'allow',
    unknown: p.unknown ?? 'review',
    review_findings: p.review_findings ?? false,
    rules: (p.rules ?? []).map((r) => ({ ...r, scopes: r.scopes ?? [] })),
  }
}

/** The first invalid rule as [index, i18n key], or null. */
export function firstRuleError(rules: LicenseRule[]): [number, string] | null {
  for (let i = 0; i < rules.length; i++) {
    const e = validateRuleMatch(rules[i].match)
    if (e) return [i, e]
  }
  return null
}

export function LicensePolicyForm({
  initial,
  etag,
  formId,
  canEdit,
  onSaved,
  onStatusChange,
}: {
  initial: LicensePolicy
  etag?: string
  formId: string
  canEdit: boolean
  onSaved?: () => void
  onStatusChange?: (s: LicensePolicyFormStatus) => void
}) {
  const { t } = useTranslation()
  const start = useMemo(() => normalize(initial), [initial])
  const [form, setForm] = useState(start)
  const [submitting, setSubmitting] = useState(false)
  const dirty = JSON.stringify(form) !== JSON.stringify(start)

  useEffect(() => {
    onStatusChange?.({ dirty, submitting })
  }, [dirty, submitting, onStatusChange])

  const actionLabel = (a: string) =>
    ({
      allow: t('licensePolicy.action.allow', 'Allow'),
      review: t('licensePolicy.action.review', 'Review'),
      deny: t('licensePolicy.action.deny', 'Deny'),
    })[a] ?? a
  const scopeLabel = (s: string) =>
    ({
      runtime: t('components.scope.runtime', 'Runtime'),
      development: t('components.scope.development', 'Development'),
      test: t('components.scope.test', 'Test'),
      optional: t('components.scope.optional', 'Optional'),
      build: t('components.scope.build', 'Build'),
      provided: t('components.scope.provided', 'Provided'),
    })[s] ?? s

  const setRule = (i: number, patch: Partial<LicenseRule>) =>
    setForm((f) => ({ ...f, rules: f.rules.map((r, n) => (n === i ? { ...r, ...patch } : r)) }))
  const move = (i: number, d: -1 | 1) =>
    setForm((f) => {
      const rules = [...f.rules]
      const j = i + d
      if (j < 0 || j >= rules.length) return f
      ;[rules[i], rules[j]] = [rules[j], rules[i]]
      return { ...f, rules }
    })

  const ruleError = firstRuleError(form.rules)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!canEdit || ruleError) return
    setSubmitting(true)
    try {
      const payload: LicensePolicy = {
        ...form,
        rules: form.rules.map((r) => ({
          match: r.match.trim(),
          action: r.action,
          ...(r.scopes && r.scopes.length > 0 ? { scopes: r.scopes } : {}),
        })),
      }
      const res = await updateLicensePolicy(payload, etag)
      if (res.evaluation_error) {
        toast.warning(
          t(
            'licensePolicy.savedNotEvaluated',
            'Saved. Evaluating the inventory did not finish; it runs again on the next package write.'
          )
        )
      } else if (res.evaluation) {
        toast.success(
          t(
            'licensePolicy.saved',
            'Saved: {violations} packages flagged, {created} findings opened, {resolved} resolved.',
            {
              violations: res.evaluation.violations,
              created: res.evaluation.findings_created,
              resolved: res.evaluation.findings_resolved,
            }
          )
        )
      } else {
        toast.success(t('licensePolicy.savedPlain', 'License policy saved.'))
      }
      onSaved?.()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('licensePolicy.saveFailed', 'The license policy could not be saved.')
        )
      )
      onSaved?.()
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form id={formId} onSubmit={submit} className="space-y-6">
      <SettingsSection
        title={t('licensePolicy.section.general', 'Policy')}
        description={t(
          'licensePolicy.section.generalHelp',
          'Judges the licenses each package declares. A denied license opens a high finding per asset and package.'
        )}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="lp-enabled">{t('licensePolicy.enabled', 'Evaluate licenses')}</Label>
            <Switch
              id="lp-enabled"
              checked={form.enabled}
              disabled={!canEdit}
              onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: v }))}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="lp-default">
                {t('licensePolicy.default', 'Known license no rule matches')}
              </Label>
              <Select
                value={form.default}
                disabled={!canEdit}
                onValueChange={(v) => setForm((f) => ({ ...f, default: v as 'allow' | 'review' }))}
              >
                <SelectTrigger id="lp-default">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(['allow', 'review'] as const).map((a) => (
                    <SelectItem key={a} value={a}>
                      {actionLabel(a)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="lp-unknown">
                {t('licensePolicy.unknown', 'Unknown or missing license')}
              </Label>
              <Select
                value={form.unknown}
                disabled={!canEdit}
                onValueChange={(v) => setForm((f) => ({ ...f, unknown: v as 'review' | 'deny' }))}
              >
                <SelectTrigger id="lp-unknown">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(['review', 'deny'] as const).map((a) => (
                    <SelectItem key={a} value={a}>
                      {actionLabel(a)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center justify-between gap-4">
            <div>
              <Label htmlFor="lp-review">
                {t('licensePolicy.reviewFindings', 'Open findings for review verdicts')}
              </Label>
              <p className="text-xs text-muted-foreground">
                {t(
                  'licensePolicy.reviewFindingsHelp',
                  'Medium findings; otherwise review verdicts only show in the inventory.'
                )}
              </p>
            </div>
            <Switch
              id="lp-review"
              checked={form.review_findings}
              disabled={!canEdit}
              onCheckedChange={(v) => setForm((f) => ({ ...f, review_findings: v }))}
            />
          </div>
        </div>
      </SettingsSection>

      <SettingsSection
        title={t('licensePolicy.section.rules', 'Rules')}
        description={t(
          'licensePolicy.section.rulesHelp',
          'An SPDX id (MIT, GPL-2.0-only WITH Classpath-exception-2.0) or a category (category:copyleft). A rule for an id beats a category rule; for the same match the first rule that applies to the dependency scope wins. In MIT OR GPL-3.0-only the most permissive allowed choice counts.'
        )}
      >
        <div className="space-y-3">
          {form.rules.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {t(
                'licensePolicy.noRules',
                'No rules: every known license gets the default verdict.'
              )}
            </p>
          )}
          {form.rules.map((r, i) => {
            const err = ruleError && ruleError[0] === i ? ruleError[1] : null
            return (
              <div key={i} className="space-y-2 rounded-md border p-3">
                <div className="flex flex-wrap items-start gap-2">
                  <div className="min-w-48 flex-1 space-y-1">
                    <Input
                      aria-label={t('licensePolicy.match', 'License or category, rule {n}', {
                        n: i + 1,
                      })}
                      value={r.match}
                      placeholder="GPL-3.0-only"
                      disabled={!canEdit}
                      aria-invalid={err ? true : undefined}
                      onChange={(e) => setRule(i, { match: e.target.value })}
                    />
                    {err && <p className="text-xs text-destructive">{t(err)}</p>}
                  </div>
                  <Select
                    value={r.action}
                    disabled={!canEdit}
                    onValueChange={(v) => setRule(i, { action: v as LicenseAction })}
                  >
                    <SelectTrigger
                      className="w-32"
                      aria-label={t('licensePolicy.actionLabel', 'Action, rule {n}', { n: i + 1 })}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(['allow', 'review', 'deny'] as const).map((a) => (
                        <SelectItem key={a} value={a}>
                          {actionLabel(a)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {canEdit && (
                    <div className="flex">
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label={t('licensePolicy.up', 'Move rule {n} up', { n: i + 1 })}
                        disabled={i === 0}
                        onClick={() => move(i, -1)}
                      >
                        <ArrowUp className="h-4 w-4" aria-hidden />
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label={t('licensePolicy.down', 'Move rule {n} down', { n: i + 1 })}
                        disabled={i === form.rules.length - 1}
                        onClick={() => move(i, 1)}
                      >
                        <ArrowDown className="h-4 w-4" aria-hidden />
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        aria-label={t('licensePolicy.remove', 'Remove rule {n}', { n: i + 1 })}
                        onClick={() =>
                          setForm((f) => ({ ...f, rules: f.rules.filter((_, n) => n !== i) }))
                        }
                      >
                        <Trash2 className="h-4 w-4" aria-hidden />
                      </Button>
                    </div>
                  )}
                </div>
                <fieldset className="flex flex-wrap gap-3">
                  <legend className="sr-only">
                    {t('licensePolicy.scopes', 'Dependency scopes')}
                  </legend>
                  <span className="text-xs text-muted-foreground">
                    {t('licensePolicy.scopesHelp', 'Only for (none: every scope):')}
                  </span>
                  {DEPENDENCY_SCOPES.map((s) => {
                    const id = `lp-${i}-${s}`
                    const checked = (r.scopes ?? []).includes(s)
                    return (
                      <div key={s} className="flex items-center gap-1.5">
                        <Checkbox
                          id={id}
                          checked={checked}
                          disabled={!canEdit}
                          onCheckedChange={(v) =>
                            setRule(i, {
                              scopes: v
                                ? [...(r.scopes ?? []), s]
                                : (r.scopes ?? []).filter((x) => x !== s),
                            })
                          }
                        />
                        <Label htmlFor={id} className="text-xs font-normal">
                          {scopeLabel(s)}
                        </Label>
                      </div>
                    )
                  })}
                </fieldset>
              </div>
            )
          })}
          {canEdit && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={form.rules.length >= MAX_LICENSE_RULES}
              onClick={() =>
                setForm((f) => ({
                  ...f,
                  rules: [...f.rules, { match: '', action: 'deny', scopes: [] }],
                }))
              }
            >
              <Plus className="me-1 h-4 w-4" aria-hidden />
              {t('licensePolicy.addRule', 'Add rule')}
            </Button>
          )}
        </div>
      </SettingsSection>
    </form>
  )
}
