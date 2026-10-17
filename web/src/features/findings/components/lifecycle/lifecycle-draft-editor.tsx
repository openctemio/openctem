'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowRight, Loader2, Pencil, Plus, ShieldCheck, Trash2, Upload } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { SettingsSection } from '@/features/shared'
import {
  CANONICAL_STATUSES,
  createLifecycleDraft,
  saveLifecycleDraft,
  statusOfRef,
  statusRef,
  subStatusName,
  testLifecycleVersion,
  type Lifecycle,
  type LifecycleSpec,
  type LifecycleSubStatus,
  type LifecycleTransition,
  type LifecycleValidationResult,
  type LifecycleVersion,
  type PersonMoves,
} from '../../api/use-finding-lifecycles'
import { isConflictError, isPlanLimitError } from '../../lib/lifecycle'
import { LifecycleValidationPanel } from './lifecycle-validation-panel'
import { PublishDialog } from './publish-dialog'
import { SubStatusPill } from './sub-status-pill'
import { TransitionDialog, type PlaceOption } from './transition-dialog'

const NO_DEFAULT = '__status__'

interface LifecycleDraftEditorProps {
  lifecycle: Lifecycle
  catalog: LifecycleSubStatus[]
  canWrite: boolean
  /** Re-read the lifecycle (after a conflict, a new draft or a publish). */
  onReload: () => void
}

function emptySpec(): LifecycleSpec {
  return { sub_statuses: [], defaults: {}, person_moves: 'canonical_plus_listed', transitions: [] }
}

function normalize(spec: LifecycleSpec | undefined): LifecycleSpec {
  const s = spec ?? emptySpec()
  return {
    sub_statuses: s.sub_statuses ?? [],
    defaults: s.defaults ?? {},
    person_moves: s.person_moves || 'canonical_plus_listed',
    transitions: s.transitions ?? [],
  }
}

/**
 * Edits a lifecycle's draft: which sub-statuses it uses, the default label
 * of each status, whether people keep every platform move, and the listed
 * moves with their requirements. Saving sends the hash read (If-Match), so a
 * draft another administrator changed meanwhile is never overwritten.
 */
export function LifecycleDraftEditor({
  lifecycle,
  catalog,
  canWrite,
  onReload,
}: LifecycleDraftEditorProps) {
  const { t, locale } = useTranslation()
  const draft = lifecycle.draft
  // Without a draft the published version is shown, read-only.
  const shown = draft ?? lifecycle.published
  const [spec, setSpec] = useState<LifecycleSpec>(() => normalize(shown?.spec))
  const [hash, setHash] = useState(draft?.spec_hash ?? '')
  const [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState<'save' | 'test' | 'draft' | null>(null)
  const [result, setResult] = useState<LifecycleValidationResult | null>(null)
  const [conflict, setConflict] = useState(false)
  const [editing, setEditing] = useState<{ index: number | null } | null>(null)
  const [publishing, setPublishing] = useState(false)

  useEffect(() => {
    setSpec(normalize(shown?.spec))
    setHash(draft?.spec_hash ?? '')
    setDirty(false)
    setResult(null)
    setConflict(false)
  }, [shown?.spec, draft?.spec_hash, draft?.version])

  const byId = useMemo(() => new Map(catalog.map((s) => [s.id, s])), [catalog])

  const update = useCallback((fn: (s: LifecycleSpec) => LifecycleSpec) => {
    setSpec((cur) => fn(cur))
    setDirty(true)
  }, [])

  const placeLabel = useCallback(
    (ref: string) => {
      const st = statusOfRef(ref)
      if (st) return t(`findings.status.${st}`, st)
      const s = byId.get(ref)
      if (!s) return ref
      return `${subStatusName(s, locale)} (${t(`findings.status.${s.canonical_status}`, s.canonical_status)})`
    },
    [byId, locale, t]
  )

  const places: PlaceOption[] = useMemo(() => {
    const out: PlaceOption[] = []
    for (const st of CANONICAL_STATUSES) {
      out.push({ ref: statusRef(st), label: placeLabel(statusRef(st)) })
      for (const id of spec.sub_statuses) {
        if (byId.get(id)?.canonical_status === st) out.push({ ref: id, label: placeLabel(id) })
      }
    }
    return out
  }, [byId, placeLabel, spec.sub_statuses])

  const readOnly = !canWrite || !draft

  const startDraft = !draft ? (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-dashed p-4">
      <p className="text-sm text-muted-foreground">
        {t(
          'findingLifecycle.draft.none',
          'This is the version in force. Start a draft to change it.'
        )}
      </p>
      {canWrite && (
        <Button
          size="sm"
          disabled={busy !== null}
          onClick={async () => {
            setBusy('draft')
            try {
              await createLifecycleDraft(lifecycle.id)
              onReload()
            } catch (err) {
              toast.error(
                getErrorMessage(
                  err,
                  t('findingLifecycle.draft.startFailed', 'Could not start a draft')
                )
              )
            } finally {
              setBusy(null)
            }
          }}
        >
          {busy === 'draft' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {t('findingLifecycle.draft.start', 'Start a draft')}
        </Button>
      )}
    </div>
  ) : null

  const save = async (): Promise<LifecycleVersion | null> => {
    if (!draft) return null
    setBusy('save')
    setConflict(false)
    try {
      const res = await saveLifecycleDraft(lifecycle.id, draft.version, hash, spec)
      if (res.version) setHash(res.version.spec_hash)
      setResult(res)
      setDirty(false)
      toast.success(t('findingLifecycle.draft.saved', 'Draft saved'))
      return res.version ?? null
    } catch (err) {
      if (isConflictError(err)) setConflict(true)
      else if (isPlanLimitError(err))
        toast.error(
          t(
            'findingLifecycle.plan.guardsUnavailable',
            'This is not available for this organization. Ask your administrator.'
          )
        )
      else
        toast.error(
          getErrorMessage(err, t('findingLifecycle.draft.saveFailed', 'Could not save the draft'))
        )
      return null
    } finally {
      setBusy(null)
    }
  }

  const check = async () => {
    if (!draft) return
    if (dirty && !(await save())) return
    setBusy('test')
    try {
      setResult(await testLifecycleVersion(lifecycle.id, draft.version))
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findingLifecycle.validation.failed', 'Could not check the draft'))
      )
    } finally {
      setBusy(null)
    }
  }

  const usedByStatus = (st: string) =>
    spec.sub_statuses.filter((id) => byId.get(id)?.canonical_status === st)

  const toggleUsed = (id: string, on: boolean) =>
    update((s) => {
      const used = on ? [...s.sub_statuses, id] : s.sub_statuses.filter((x) => x !== id)
      const defaults = { ...(s.defaults ?? {}) }
      if (!on) for (const [k, v] of Object.entries(defaults)) if (v === id) delete defaults[k]
      return { ...s, sub_statuses: used, defaults }
    })

  const guardSummary = (tr: LifecycleTransition) => {
    const out: string[] = []
    for (const g of tr.guards ?? []) {
      if (g.kind === 'require_note')
        out.push(t('findingLifecycle.guardSummary.note', 'Note ≥ {n}', { n: g.min_len ?? 0 }))
      if (g.kind === 'require_fields')
        for (const f of g.fields ?? []) out.push(t(`findingLifecycle.field.${f}`, f))
      if (g.kind === 'require_permission')
        out.push(t('findingLifecycle.guardSummary.permission', 'Permission'))
      if (g.kind === 'deny_actor_kinds')
        out.push(t('findingLifecycle.guardSummary.denyKinds', 'People only'))
    }
    if (tr.when?.length)
      out.push(t('findingLifecycle.guardSummary.when', '{n} condition(s)', { n: tr.when.length }))
    return out
  }

  const liveCatalog = catalog.filter((s) => !s.archived || spec.sub_statuses.includes(s.id))
  const publishable = !dirty && result?.valid === true

  return (
    <div className="space-y-6">
      {startDraft}
      {conflict && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm"
        >
          <span>
            {t(
              'findingLifecycle.draft.conflict',
              'Someone else changed this draft since you opened it. Reload to see their version; your changes here are not saved.'
            )}
          </span>
          <Button size="sm" variant="outline" onClick={onReload}>
            {t('findingLifecycle.draft.reload', 'Reload')}
          </Button>
        </div>
      )}

      <SettingsSection
        title={t('findingLifecycle.draft.subStatusesTitle', 'Sub-statuses in this lifecycle')}
        description={t(
          'findingLifecycle.draft.subStatusesHint',
          'Pick the labels this lifecycle uses and the one each status starts on.'
        )}
      >
        {liveCatalog.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t(
              'findingLifecycle.draft.noCatalog',
              'Add sub-statuses first, in the Sub-statuses tab.'
            )}
          </p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {CANONICAL_STATUSES.map((st) => {
              const lane = liveCatalog.filter((s) => s.canonical_status === st)
              if (lane.length === 0) return null
              const used = usedByStatus(st)
              return (
                <div key={st} className="space-y-2 rounded-lg border p-3">
                  <div className="text-sm font-semibold">{t(`findings.status.${st}`, st)}</div>
                  {lane.map((s) => (
                    <label key={s.id} className="flex min-w-0 items-center gap-2">
                      <Checkbox
                        checked={spec.sub_statuses.includes(s.id)}
                        disabled={readOnly}
                        onCheckedChange={(v) => toggleUsed(s.id, v === true)}
                        aria-label={t('findingLifecycle.draft.use', 'Use {name}', {
                          name: subStatusName(s, locale),
                        })}
                      />
                      <SubStatusPill subStatus={s} />
                    </label>
                  ))}
                  {used.length > 0 && (
                    <div className="space-y-1 pt-1">
                      <Label className="text-xs text-muted-foreground">
                        {t('findingLifecycle.draft.default', 'Starts on')}
                      </Label>
                      <Select
                        value={spec.defaults?.[st] ?? NO_DEFAULT}
                        disabled={readOnly}
                        onValueChange={(v) =>
                          update((s) => {
                            const defaults = { ...(s.defaults ?? {}) }
                            if (v === NO_DEFAULT) delete defaults[st]
                            else defaults[st] = v
                            return { ...s, defaults }
                          })
                        }
                      >
                        <SelectTrigger
                          className="h-8 w-full"
                          aria-label={t('findingLifecycle.draft.defaultOf', 'Default of {status}', {
                            status: t(`findings.status.${st}`, st),
                          })}
                        >
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NO_DEFAULT}>
                            {t('findingLifecycle.draft.statusItself', 'The status itself')}
                          </SelectItem>
                          {used.map((id) => (
                            <SelectItem key={id} value={id}>
                              {byId.get(id) ? subStatusName(byId.get(id)!, locale) : id}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </SettingsSection>

      <SettingsSection
        title={t('findingLifecycle.draft.movesTitle', 'Moves')}
        description={t(
          'findingLifecycle.draft.movesHint',
          'Listed moves add requirements; the platform still decides first.'
        )}
        actions={
          !readOnly && (
            <Button
              size="sm"
              variant="outline"
              disabled={spec.transitions.length >= 60}
              onClick={() => setEditing({ index: null })}
            >
              <Plus className="mr-1 size-3.5" />
              {t('findingLifecycle.draft.addMove', 'Add move')}
            </Button>
          )
        }
      >
        <RadioGroup
          value={spec.person_moves}
          disabled={readOnly}
          onValueChange={(v) => update((s) => ({ ...s, person_moves: v as PersonMoves }))}
          className="grid gap-2 sm:grid-cols-2"
        >
          {(['canonical_plus_listed', 'listed_only'] as const).map((m) => (
            <label key={m} className="flex items-start gap-2 rounded-lg border p-3 text-sm">
              <RadioGroupItem value={m} className="mt-0.5" />
              <span>
                <span className="font-medium">{t(`findingLifecycle.personMoves.${m}`, m)}</span>
                <span className="block text-xs text-muted-foreground">
                  {t(`findingLifecycle.personMoves.${m}Hint`, '')}
                </span>
              </span>
            </label>
          ))}
        </RadioGroup>

        {spec.transitions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t('findingLifecycle.draft.noMoves', 'No listed moves: people use the platform moves.')}
          </p>
        ) : (
          <ul className="divide-y rounded-lg border">
            {spec.transitions.map((tr, i) => (
              <li key={tr.id || i} className="flex flex-wrap items-start justify-between gap-2 p-3">
                <div className="min-w-0 space-y-1">
                  <div className="text-sm font-medium">{tr.name}</div>
                  <div className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                    <span className="truncate">{tr.from.map(placeLabel).join(', ')}</span>
                    <ArrowRight className="size-3 shrink-0" aria-hidden />
                    <span className="truncate">{placeLabel(tr.to)}</span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {guardSummary(tr).map((g, n) => (
                      <Badge key={n} variant="outline" className="text-xs font-normal">
                        {g}
                      </Badge>
                    ))}
                  </div>
                </div>
                {!readOnly && (
                  <div className="flex shrink-0 gap-1">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-8"
                      aria-label={t('findingLifecycle.draft.editMove', 'Edit {name}', {
                        name: tr.name,
                      })}
                      onClick={() => setEditing({ index: i })}
                    >
                      <Pencil className="size-4" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="size-8"
                      aria-label={t('findingLifecycle.draft.removeMove', 'Remove {name}', {
                        name: tr.name,
                      })}
                      onClick={() =>
                        update((s) => ({
                          ...s,
                          transitions: s.transitions.filter((_, j) => j !== i),
                        }))
                      }
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </SettingsSection>

      {draft && (
        <SettingsSection
          title={t('findingLifecycle.validation.title', 'Check and publish')}
          actions={
            canWrite && (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null || !dirty}
                  onClick={() => void save()}
                >
                  {busy === 'save' && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {t('findingLifecycle.draft.save', 'Save draft')}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  onClick={() => void check()}
                >
                  {busy === 'test' ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <ShieldCheck className="mr-1 size-3.5" />
                  )}
                  {t('findingLifecycle.validation.run', 'Check')}
                </Button>
                <Button
                  size="sm"
                  disabled={busy !== null || !publishable}
                  title={
                    publishable
                      ? undefined
                      : t('findingLifecycle.publish.needsCheck', 'Save and check the draft first')
                  }
                  onClick={() => setPublishing(true)}
                >
                  <Upload className="mr-1 size-3.5" />
                  {t('findingLifecycle.publish.confirm', 'Publish')}
                </Button>
              </>
            )
          }
        >
          {dirty && (
            <p className="text-xs text-warning">
              {t('findingLifecycle.draft.unsaved', 'Unsaved changes')}
            </p>
          )}
          <LifecycleValidationPanel result={result} />
        </SettingsSection>
      )}
      <TransitionDialog
        open={editing !== null}
        onOpenChange={(o) => !o && setEditing(null)}
        transition={editing?.index != null ? spec.transitions[editing.index] : undefined}
        places={places}
        takenIds={spec.transitions.filter((_, j) => j !== editing?.index).map((x) => x.id)}
        onSave={(tr) =>
          update((s) => {
            const transitions = [...s.transitions]
            if (editing?.index != null) transitions[editing.index] = tr
            else transitions.push(tr)
            return { ...s, transitions }
          })
        }
      />
      {draft && (
        <PublishDialog
          open={publishing}
          onOpenChange={setPublishing}
          lifecycleId={lifecycle.id}
          version={draft.version}
          onPublished={() => {
            toast.success(t('findingLifecycle.publish.done', 'Lifecycle published'))
            onReload()
          }}
        />
      )}
    </div>
  )
}
