'use client'

import { useEffect, useMemo, useState } from 'react'
import { useSWRConfig } from 'swr'
import { useForm, useFieldArray, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Plus, X, Lock, Info, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
  SheetBody,
  SheetForm,
} from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { DynamicListInput } from '@/components/ui/dynamic-list-input'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { put } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'

import type { CtemCycle } from '../types'
import { CharterOutcome } from './charter-outcome'
import { useCycleStatusLabel } from './cycle-status-badge'
import { InScopeServicesField } from './in-scope-services-field'
import { CharterAttackerProfilesField } from './charter-attacker-profiles-field'
import { CharterExclusionsField } from './charter-exclusions-field'
import { cycleKey, syncCycleProfiles, useCycleProfiles } from '../api'
import {
  charterFormSchema,
  charterToForm,
  formToCharter,
  charterWarnings,
  type CharterFormData,
} from '../charter.schema'

interface CharterEditorSheetProps {
  cycle: CtemCycle | null
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Called after a successful save so the parent can revalidate its list. */
  onSaved?: () => void
}

/** Read-only rendering of a string list (used when the charter is frozen). */
function NotSet() {
  const { t } = useTranslation()
  return <p className="text-sm text-muted-foreground">{t('scoping.charter.notSet', 'Not set')}</p>
}

function ReadOnlyList({ items }: { items: string[] }) {
  const filled = items.filter((s) => s.trim().length > 0)
  if (filled.length === 0) {
    return <NotSet />
  }
  return (
    <ul className="list-disc space-y-1 ps-5 text-sm">
      {filled.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </ul>
  )
}

function ReadOnlyText({ value }: { value: string }) {
  if (!value.trim()) return <NotSet />
  return <p className="whitespace-pre-wrap text-sm">{value}</p>
}

/**
 * CharterEditorSheet edits the ctem.org scope-charter for a cycle: what it
 * defends against (threat scenarios), how success is measured, what is
 * deliberately excluded and why, who owns escalation, and the accountable
 * roles. The charter freezes on Activate, so all controls are read-only unless
 * the cycle is in `planning` (matching the API, which only updates the charter
 * WHERE status = 'planning').
 */
export function CharterEditorSheet({
  cycle,
  open,
  onOpenChange,
  onSaved,
}: CharterEditorSheetProps) {
  const { t } = useTranslation()
  const statusLabel = useCycleStatusLabel()
  const { can } = usePermissions()
  const isPlanning = cycle?.status === 'planning'
  const canWrite = can(Permission.CTEMCyclesWrite)
  const editable = isPlanning && canWrite

  const form = useForm<CharterFormData>({
    resolver: zodResolver(charterFormSchema),
    defaultValues: charterToForm(cycle?.charter),
  })

  const {
    control,
    handleSubmit,
    reset,
    watch,
    formState: { isSubmitting },
  } = form

  // Re-hydrate whenever a different cycle is opened.
  useEffect(() => {
    if (open) reset(charterToForm(cycle?.charter))
  }, [open, cycle, reset])

  // The attacker profiles the cycle assumes are links (ctem_cycle_attacker_profiles),
  // not charter text: loaded with the sheet, written on Save after the charter.
  const { mutate: mutateCache } = useSWRConfig()
  const { data: linkedProfiles } = useCycleProfiles(open && cycle ? cycle.id : null)
  const savedProfileIds = useMemo(
    () => (linkedProfiles?.data ?? []).map((p) => p.id),
    [linkedProfiles]
  )
  const [profileIds, setProfileIds] = useState<string[]>([])
  useEffect(() => {
    if (open) setProfileIds(savedProfileIds)
  }, [open, savedProfileIds])

  const successCriteria = useFieldArray({ control, name: 'success_criteria' })

  const watched = watch()
  const warnings = useMemo(() => charterWarnings(watched), [watched])

  const onSubmit = async (data: CharterFormData) => {
    if (!cycle) return
    try {
      // The cycle Update endpoint rewrites name/dates alongside the charter, so
      // echo the current values back to avoid blanking them.
      await put(`/api/v1/ctem-cycles/${cycle.id}`, {
        name: cycle.name,
        start_date: cycle.start_date || '',
        end_date: cycle.end_date || '',
        charter: formToCharter(data),
      })
      await syncCycleProfiles(cycle.id, savedProfileIds, profileIds)
      await mutateCache(`${cycleKey(cycle.id)}/profiles`)
      toast.success(t('scoping.charter.saved', 'Charter saved.'))
      onSaved?.()
      onOpenChange(false)
    } catch (err) {
      toast.error(getErrorMessage(err, t('scoping.charter.saveFailed', 'Failed to save charter')))
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-2xl"
        onInteractOutside={(e) => {
          if (isSubmitting) e.preventDefault()
        }}
      >
        <SheetHeader>
          <div className="flex items-center gap-2">
            <SheetTitle>{t('scoping.charter.title', 'Cycle charter')}</SheetTitle>
            {cycle && <Badge variant="outline">{statusLabel(cycle.status)}</Badge>}
          </div>
          <SheetDescription>
            {cycle?.name
              ? t(
                  'scoping.charter.descriptionNamed',
                  'Scope charter for "{name}": attacker profiles, measurable success criteria, reasoned exclusions, escalation and roles.',
                  { name: cycle.name }
                )
              : t('scoping.charter.description', 'Scope charter for this cycle.')}
          </SheetDescription>
        </SheetHeader>

        <SheetForm onSubmit={handleSubmit(onSubmit)}>
          <SheetBody className="space-y-4">
            {!editable && (
              <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-sm">
                <Lock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                <span className="text-muted-foreground">
                  {isPlanning
                    ? t(
                        'scoping.charter.noPermission',
                        'You do not have permission to edit this charter.'
                      )
                    : t(
                        'scoping.charter.frozen',
                        'The charter is frozen. It can only be edited while the cycle is in planning, and activating the cycle locks it.'
                      )}
                </span>
              </div>
            )}

            {cycle?.charter_evaluation && <CharterOutcome evaluation={cycle.charter_evaluation} />}

            {/* Scope & objectives */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('scoping.charter.scopeObjectives', 'Scope and objectives')}
                </CardTitle>
                <CardDescription>
                  {t('scoping.charter.scopeHint', 'Frame scope by what the cycle defends against.')}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>{t('scoping.charter.profiles', 'Attacker profiles')}</Label>
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'scoping.charter.profilesHint',
                      'Who this cycle defends against. The threat model reasons over the same profiles.'
                    )}
                  </p>
                  <CharterAttackerProfilesField
                    value={profileIds}
                    onChange={setProfileIds}
                    editable={editable}
                  />
                  <LegacyThreatScenarios control={control} editable={editable} />
                </div>
                <ListField
                  control={control}
                  name="objectives"
                  label={t('scoping.charter.objectives', 'Objectives')}
                  placeholder={t(
                    'scoping.charter.objectivesPlaceholder',
                    'e.g. Reduce KEV exposure on internet-facing assets'
                  )}
                  addLabel={t('scoping.charter.addObjective', 'Add objective')}
                  editable={editable}
                  numbered
                />
                <ListField
                  control={control}
                  name="business_priorities"
                  label={t('scoping.charter.priorities', 'Business priorities')}
                  placeholder={t(
                    'scoping.charter.prioritiesPlaceholder',
                    'e.g. Protect the customer payment platform'
                  )}
                  addLabel={t('scoping.charter.addPriority', 'Add business priority')}
                  editable={editable}
                />
                <Controller
                  control={control}
                  name="in_scope_services"
                  render={({ field }) => (
                    <InScopeServicesField
                      value={field.value}
                      onChange={field.onChange}
                      editable={editable}
                    />
                  )}
                />
              </CardContent>
            </Card>

            {/* Risk & success */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('scoping.charter.riskSuccess', 'Risk and success')}
                </CardTitle>
                <CardDescription>
                  {t(
                    'scoping.charter.riskSuccessHint',
                    'How much risk is acceptable and how success is measured.'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="risk_appetite">
                    {t('scoping.charter.riskAppetite', 'Risk appetite')}
                  </Label>
                  {editable ? (
                    <Controller
                      control={control}
                      name="risk_appetite"
                      render={({ field }) => (
                        <Textarea
                          id="risk_appetite"
                          placeholder={t(
                            'scoping.charter.riskAppetitePlaceholder',
                            'e.g. No critical KEV exposures tolerated on internet-facing assets. Medium risk accepted internally.'
                          )}
                          className="min-h-16"
                          {...field}
                        />
                      )}
                    />
                  ) : (
                    <ReadOnlyText value={watched.risk_appetite} />
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label>{t('scoping.charter.criteria', 'Success criteria')}</Label>
                    <span className="text-xs text-muted-foreground">
                      {t(
                        'scoping.charter.criteriaHint',
                        'Checked at close: name, metric and target'
                      )}
                    </span>
                  </div>
                  {editable ? (
                    <div className="space-y-3">
                      {successCriteria.fields.map((row, index) => (
                        <div
                          key={row.id}
                          className="grid grid-cols-1 gap-2 rounded-md border border-border p-3 sm:grid-cols-[1fr_1fr_1fr_auto]"
                        >
                          <Controller
                            control={control}
                            name={`success_criteria.${index}.name`}
                            render={({ field }) => (
                              <Input
                                placeholder={t(
                                  'scoping.charter.criterionName',
                                  'Name (e.g. KEV remediation)'
                                )}
                                {...field}
                              />
                            )}
                          />
                          <Controller
                            control={control}
                            name={`success_criteria.${index}.metric`}
                            render={({ field }) => (
                              <Input
                                placeholder={t(
                                  'scoping.charter.criterionMetric',
                                  'Metric (e.g. MTTR, P0 resolved)'
                                )}
                                {...field}
                              />
                            )}
                          />
                          <Controller
                            control={control}
                            name={`success_criteria.${index}.target`}
                            render={({ field }) => (
                              <Input
                                placeholder={t(
                                  'scoping.charter.criterionTarget',
                                  'Target (e.g. < 14 days)'
                                )}
                                {...field}
                              />
                            )}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 shrink-0"
                            onClick={() => successCriteria.remove(index)}
                            aria-label={t(
                              'scoping.charter.removeCriterion',
                              'Remove success criterion'
                            )}
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="w-fit"
                        onClick={() => successCriteria.append({ name: '', metric: '', target: '' })}
                      >
                        <Plus className="h-4 w-4" />
                        {t('scoping.charter.addCriterion', 'Add success criterion')}
                      </Button>
                      <p className="text-xs text-muted-foreground">
                        {t(
                          'scoping.charter.metricsHelp',
                          'Metrics checked automatically when the cycle closes: MTTR, P0/P1 resolved, P0/P1 open, findings resolved/opened, validation coverage, risk reduction, risk after. Targets like "< 14 days", ">= 90%" or "0". Anything else is recorded as not measurable.'
                        )}
                      </p>
                    </div>
                  ) : watched.success_criteria.filter((c) => c.name || c.metric || c.target)
                      .length === 0 ? (
                    <NotSet />
                  ) : (
                    <ul className="space-y-1 text-sm">
                      {watched.success_criteria
                        .filter((c) => c.name || c.metric || c.target)
                        .map((c, i) => (
                          <li key={i}>
                            <span className="font-medium">
                              {c.name || t('scoping.charter.untitled', 'Untitled')}
                            </span>
                            {(c.metric || c.target) && (
                              <span className="text-muted-foreground">
                                {' '}
                                ·{' '}
                                {t('scoping.charter.metricTarget', '{metric}: {target}', {
                                  metric: c.metric || t('scoping.charter.noMetric', 'no metric'),
                                  target: c.target || t('scoping.charter.noTarget', 'no target'),
                                })}
                              </span>
                            )}
                          </li>
                        ))}
                    </ul>
                  )}

                  {editable && warnings.length > 0 && (
                    <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-2 text-xs text-muted-foreground">
                      <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <ul className="space-y-1">
                        {warnings.map((w, i) => (
                          <li key={i}>{w}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Exclusions */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('scoping.charter.exclusions', 'Exclusions')}
                </CardTitle>
                <CardDescription>
                  {t(
                    'scoping.charter.exclusionsHint',
                    'What is deliberately out of scope, picked from the exclusions scans enforce, and the reason, so a deferral is a decision and not a silent gap.'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Controller
                  control={control}
                  name="exclusions"
                  render={({ field }) => (
                    <CharterExclusionsField
                      value={field.value}
                      onChange={field.onChange}
                      editable={editable}
                    />
                  )}
                />
              </CardContent>
            </Card>

            {/* Governance */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  {t('scoping.charter.governance', 'Escalation, roles and timeline')}
                </CardTitle>
                <CardDescription>
                  {t(
                    'scoping.charter.governanceHint',
                    'Who owns the cycle and where blockers escalate.'
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="escalation_path">
                    {t('scoping.charter.escalation', 'Escalation path')}
                  </Label>
                  {editable ? (
                    <Controller
                      control={control}
                      name="escalation_path"
                      render={({ field }) => (
                        <Textarea
                          id="escalation_path"
                          placeholder={t(
                            'scoping.charter.escalationPlaceholder',
                            'Who blockers escalate to (person, role or channel).'
                          )}
                          className="min-h-16"
                          {...field}
                        />
                      )}
                    />
                  ) : (
                    <ReadOnlyText value={watched.escalation_path} />
                  )}
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <RoleField
                    control={control}
                    name="roles.sponsor"
                    label={t('scoping.charter.sponsor', 'Sponsor')}
                    value={watched.roles.sponsor}
                    editable={editable}
                  />
                  <RoleField
                    control={control}
                    name="roles.operator"
                    label={t('scoping.charter.operator', 'Operator')}
                    value={watched.roles.operator}
                    editable={editable}
                  />
                  <RoleField
                    control={control}
                    name="roles.engineering_partner"
                    label={t('scoping.charter.engineeringPartner', 'Engineering partner')}
                    value={watched.roles.engineering_partner}
                    editable={editable}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="timeline">{t('scoping.charter.timeline', 'Timeline')}</Label>
                  {editable ? (
                    <Controller
                      control={control}
                      name="timeline"
                      render={({ field }) => (
                        <Input
                          id="timeline"
                          placeholder={t(
                            'scoping.charter.timelinePlaceholder',
                            'e.g. 90-day cycle, weekly triage'
                          )}
                          {...field}
                        />
                      )}
                    />
                  ) : (
                    <ReadOnlyText value={watched.timeline} />
                  )}
                </div>
              </CardContent>
            </Card>
          </SheetBody>

          <SheetFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {editable ? t('common.cancel', 'Cancel') : t('scoping.charter.close', 'Close')}
            </Button>
            {isPlanning && (
              <Can permission={Permission.CTEMCyclesWrite} mode="disable">
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                  {t('scoping.charter.save', 'Save charter')}
                </Button>
              </Can>
            )}
          </SheetFooter>
        </SheetForm>
      </SheetContent>
    </Sheet>
  )
}

/**
 * Threat scenarios typed as free text before the attacker-profile picker.
 * Shown so they are not lost, removable while the charter is editable, never
 * added to: pick an attacker profile instead.
 */
function LegacyThreatScenarios({
  control,
  editable,
}: {
  control: ReturnType<typeof useForm<CharterFormData>>['control']
  editable: boolean
}) {
  const { t } = useTranslation()
  return (
    <Controller
      control={control}
      name="threat_scenarios"
      render={({ field }) => {
        const items = field.value.filter((s) => s.trim())
        if (items.length === 0) return <></>
        return (
          <div className="space-y-1 rounded-md border bg-muted/40 p-2 text-sm">
            <p className="text-muted-foreground">
              {t('scoping.charter.legacyScenarios', 'Earlier free-text scenarios')}
            </p>
            <ul className="space-y-1">
              {items.map((item) => (
                <li key={item} className="flex items-center justify-between gap-2">
                  <span className="truncate">{item}</span>
                  {editable && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      aria-label={t('scoping.charter.removeItem', 'Remove {item}', { item })}
                      onClick={() => field.onChange(field.value.filter((v) => v !== item))}
                    >
                      <X className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )
      }}
    />
  )
}

/** String-list field: editable via DynamicListInput, read-only as a bullet list. */
function ListField({
  control,
  name,
  label,
  description,
  placeholder,
  addLabel,
  editable,
  numbered,
}: {
  control: ReturnType<typeof useForm<CharterFormData>>['control']
  name: 'objectives' | 'business_priorities'
  label: string
  description?: string
  placeholder: string
  addLabel: string
  editable: boolean
  numbered?: boolean
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      {description && <p className="text-xs text-muted-foreground">{description}</p>}
      <Controller
        control={control}
        name={name}
        render={({ field }) =>
          editable ? (
            <DynamicListInput
              items={field.value}
              onChange={field.onChange}
              placeholder={placeholder}
              addLabel={addLabel}
              numbered={numbered}
            />
          ) : (
            <ReadOnlyList items={field.value} />
          )
        }
      />
    </div>
  )
}

function RoleField({
  control,
  name,
  label,
  value,
  editable,
}: {
  control: ReturnType<typeof useForm<CharterFormData>>['control']
  name: 'roles.sponsor' | 'roles.operator' | 'roles.engineering_partner'
  label: string
  value: string
  editable: boolean
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={name}>{label}</Label>
      {editable ? (
        <Controller
          control={control}
          name={name}
          render={({ field }) => <Input id={name} placeholder={label} {...field} />}
        />
      ) : (
        <ReadOnlyText value={value} />
      )}
    </div>
  )
}
