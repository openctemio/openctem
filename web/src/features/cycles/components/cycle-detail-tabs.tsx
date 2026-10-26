'use client'

import { useMemo, useState, type ReactNode } from 'react'
import Link from '@/components/link'
import type { ColumnDef } from '@tanstack/react-table'
import { toast } from 'sonner'
import { Lock, NotebookPen, ScrollText, ShieldQuestion, Swords } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import {
  DataTable,
  DataTableColumnHeader,
  DetailSection,
  DetailSections,
  EmptyState,
  ErrorState,
} from '@/features/shared'
import { useBusinessServiceOptions } from '@/features/business-services/api/business-service-assets'
import { Can, Permission, usePermissions } from '@/lib/permissions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateOnly } from '@/lib/date-only'
import { useTranslation } from '@/context/i18n-provider'
import {
  profileTypeLabel,
  saveScopeRefinement,
  syncCycleProfiles,
  useCycleProfiles,
  useCycleScope,
  type CycleScopeItem,
} from '../api'
import type { CtemCycle } from '../types'
import { CharterOutcome } from './charter-outcome'
import { CharterExclusionsField } from './charter-exclusions-field'
import { CharterAttackerProfilesField } from './charter-attacker-profiles-field'

function NotSet() {
  const { t } = useTranslation()
  return <p className="text-sm text-muted-foreground">{t('scoping.cycleTabs.notSet', 'Not set')}</p>
}

function TextList({ items, numbered }: { items?: string[]; numbered?: boolean }) {
  const filled = (items ?? []).filter((s) => s.trim())
  if (filled.length === 0) return <NotSet />
  const List = numbered ? 'ol' : 'ul'
  return (
    <List className={`${numbered ? 'list-decimal' : 'list-disc'} space-y-1 ps-5 text-sm`}>
      {filled.map((s, i) => (
        <li key={i}>{s}</li>
      ))}
    </List>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <p className="text-xs text-muted-foreground">{label}</p>
      {children}
    </div>
  )
}

const text = (v?: string) =>
  v?.trim() ? <p className="text-sm whitespace-pre-wrap">{v}</p> : <NotSet />

/** The charter, read-only (it is edited in the charter sheet while planning). */
export function CycleCharterTab({ cycle, onEdit }: { cycle: CtemCycle; onEdit: () => void }) {
  const { t } = useTranslation()
  const charter = cycle.charter ?? {}
  const serviceIds = charter.in_scope_services ?? []
  const { data: services } = useBusinessServiceOptions(serviceIds.length > 0)
  const nameOf = useMemo(
    () => new Map((services?.data ?? []).map((s) => [s.id, s.name])),
    [services]
  )
  const planning = cycle.status === 'planning'

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
          {planning ? (
            t(
              'scoping.cycleTabs.editableUntil',
              'The charter can be edited until the cycle is activated.'
            )
          ) : (
            <>
              <Lock className="h-3.5 w-3.5" />
              {t('scoping.cycleTabs.frozen', 'Frozen when the cycle was activated.')}
            </>
          )}
        </p>
        <Button size="sm" variant="outline" onClick={onEdit}>
          <ScrollText className="me-2 h-4 w-4" />
          {planning
            ? t('scoping.cycleTabs.editCharter', 'Edit charter')
            : t('scoping.cycleTabs.openCharter', 'Open charter')}
        </Button>
      </div>
      <DetailSections>
        <DetailSection title={t('scoping.cycleTabs.scopeObjectives', 'Scope and objectives')}>
          <div className="grid gap-4 md:grid-cols-2">
            <Field label={t('scoping.cycleTabs.objectives', 'Objectives')}>
              <TextList items={charter.objectives} numbered />
            </Field>
            <Field label={t('scoping.cycleTabs.priorities', 'Business priorities')}>
              <TextList items={charter.business_priorities} />
            </Field>
            <Field label={t('scoping.cycleTabs.inScopeServices', 'In-scope services')}>
              {serviceIds.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('scoping.cycleTabs.noServices', 'None. Activating covers every asset.')}
                </p>
              ) : (
                <ul className="list-disc space-y-1 ps-5 text-sm">
                  {serviceIds.map((id) => (
                    <li key={id}>
                      {nameOf.get(id) ?? (
                        <span className="text-muted-foreground">
                          {t('scoping.cycleTabs.notAService', '{id} (not a business service)', {
                            id,
                          })}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </Field>
            <Field label={t('scoping.cycleTabs.riskAppetite', 'Risk appetite')}>
              {text(charter.risk_appetite)}
            </Field>
          </div>
        </DetailSection>
        <DetailSection
          title={t('scoping.cycleTabs.successCriteria', 'Success criteria')}
          count={charter.success_criteria?.length ?? 0}
        >
          {(charter.success_criteria ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t(
                'scoping.cycleTabs.noCriteria',
                'Not set. Criteria with a metric and a target are checked when the cycle closes.'
              )}
            </p>
          ) : (
            <ul className="space-y-1 text-sm">
              {charter.success_criteria!.map((c, i) => (
                <li key={i}>
                  <span className="font-medium">
                    {c.name || t('scoping.cycleTabs.untitled', 'Untitled')}
                  </span>
                  <span className="text-muted-foreground">
                    ,{' '}
                    {t('scoping.cycleTabs.metricTarget', '{metric}: {target}', {
                      metric: c.metric || t('scoping.cycleTabs.noMetric', 'no metric'),
                      target: c.target || t('scoping.cycleTabs.noTarget', 'no target'),
                    })}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </DetailSection>
        <DetailSection
          title={t('scoping.cycleTabs.exclusions', 'Exclusions')}
          count={charter.exclusions?.length ?? 0}
        >
          <CharterExclusionsField
            value={charter.exclusions ?? []}
            onChange={() => {}}
            editable={false}
          />
        </DetailSection>
        <DetailSection title={t('scoping.cycleTabs.governance', 'Escalation, roles and timeline')}>
          <div className="grid gap-4 md:grid-cols-3">
            <Field label={t('scoping.cycleTabs.sponsor', 'Sponsor')}>
              {text(charter.roles?.sponsor)}
            </Field>
            <Field label={t('scoping.cycleTabs.operator', 'Operator')}>
              {text(charter.roles?.operator)}
            </Field>
            <Field label={t('scoping.cycleTabs.engineeringPartner', 'Engineering partner')}>
              {text(charter.roles?.engineering_partner)}
            </Field>
            <Field label={t('scoping.cycleTabs.escalation', 'Escalation path')}>
              {text(charter.escalation_path)}
            </Field>
            <Field label={t('scoping.cycleTabs.timeline', 'Timeline')}>
              {text(charter.timeline)}
            </Field>
          </div>
        </DetailSection>
      </DetailSections>
    </div>
  )
}

/** The assets frozen into the cycle on Activate. */
export function CycleScopeTab({ cycle }: { cycle: CtemCycle }) {
  const { t, locale } = useTranslation()
  const scopeColumns = useMemo<ColumnDef<CycleScopeItem>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (r) => r.asset_name || r.asset_id,
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scoping.cycleTabs.col.asset', 'Asset')}
          />
        ),
        // An empty name means the asset was deleted after the snapshot; no name
        // field at all is an API from before the join, so link the id instead.
        cell: ({ row }) =>
          row.original.asset_name === '' ? (
            <span className="text-muted-foreground">
              {t('scoping.cycleTabs.deletedAsset', 'Deleted asset')}
            </span>
          ) : (
            <Link href={`/assets/${row.original.asset_id}`} className="font-medium hover:underline">
              {row.original.asset_name ?? (
                <span className="font-mono text-xs">{row.original.asset_id}</span>
              )}
            </Link>
          ),
      },
      {
        id: 'type',
        accessorFn: (r) => r.asset_type ?? '',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scoping.cycleTabs.col.type', 'Type')} />
        ),
        cell: ({ row }) => {
          const type = row.original.asset_type
          if (!type) return <span>—</span>
          return <span>{t(`assets.typeLabel.${type}`, type.replace(/_/g, ' '))}</span>
        },
      },
      {
        id: 'criticality',
        accessorFn: (r) => r.asset_criticality ?? '',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scoping.cycleTabs.col.criticality', 'Criticality')}
          />
        ),
        cell: ({ row }) => {
          const c = row.original.asset_criticality
          return <span>{c ? t(`criticality.${c}`, c) : '—'}</span>
        },
      },
      {
        accessorKey: 'included_at',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scoping.cycleTabs.col.frozen', 'Frozen')}
          />
        ),
        cell: ({ row }) => formatDateOnly(row.original.included_at, locale) || '—',
      },
    ],
    [t, locale]
  )
  const planning = cycle.status === 'planning'
  const { data, error, isLoading, mutate } = useCycleScope(planning ? null : cycle.id)

  if (planning) {
    const services = cycle.charter?.in_scope_services?.length ?? 0
    return (
      <EmptyState
        icon={ShieldQuestion}
        title={t('scoping.cycleTabs.scopeFrozenTitle', 'Scope is frozen on Activate')}
        description={
          services > 0
            ? t(
                'scoping.cycleTabs.scopeFrozenServices',
                'Activating snapshots the assets linked to the {n, plural, one {# in-scope service} other {# in-scope services}}. Link assets to those services under Business context first.',
                { n: services }
              )
            : t(
                'scoping.cycleTabs.scopeFrozenAll',
                'No in-scope services are chosen, so activating snapshots every asset. Pick services in the charter to narrow it.'
              )
        }
      />
    )
  }
  if (error)
    return (
      <ErrorState
        title={t('scoping.cycleTabs.scopeLoadError', 'the scope snapshot')}
        error={error}
        onRetry={() => mutate()}
      />
    )
  if (isLoading || !data) return <Skeleton className="h-48 w-full" />
  return (
    <DataTable
      columns={scopeColumns}
      data={data}
      searchPlaceholder={t('scoping.cycleTabs.scopeSearch', 'Search assets in scope…')}
      emptyMessage={t('scoping.cycleTabs.scopeEmpty', 'Nothing was frozen into scope')}
      emptyDescription={t(
        'scoping.cycleTabs.scopeEmptyHint',
        'The snapshot is empty. The in-scope services had no linked assets when the cycle was activated.'
      )}
    />
  )
}

/**
 * The attacker profiles the cycle assumes. Editable while the cycle is open
 * (planning, active, review); closed cycles are archive.
 */
export function CycleProfilesTab({ cycle }: { cycle: CtemCycle }) {
  const { t } = useTranslation()
  const { can } = usePermissions()
  const { data, error, isLoading, mutate } = useCycleProfiles(cycle.id)
  const linked = useMemo(() => data?.data ?? [], [data])
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const editable = cycle.status !== 'closed' && can(Permission.CTEMCyclesWrite)

  const save = async () => {
    setSaving(true)
    try {
      await syncCycleProfiles(
        cycle.id,
        linked.map((p) => p.id),
        draft
      )
      toast.success(t('scoping.cycleTabs.profilesSaved', 'Attacker profiles saved.'))
      setEditing(false)
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('scoping.cycleTabs.profilesSaveFailed', 'Failed to save attacker profiles')
        )
      )
    } finally {
      // A save that failed midway may have linked or unlinked some profiles:
      // always show what the server holds now.
      await mutate()
      setSaving(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          {t(
            'scoping.cycleTabs.profilesHint',
            'Who this cycle assumes it defends against. The threat model reasons over the same profiles.'
          )}
        </p>
        {editable && (
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setDraft(linked.map((p) => p.id))
              setEditing(true)
            }}
          >
            <Swords className="me-2 h-4 w-4" />
            {t('scoping.cycleTabs.chooseProfiles', 'Choose profiles')}
          </Button>
        )}
      </div>
      {error ? (
        <ErrorState
          title={t('scoping.cycleTabs.profilesLoadError', 'attacker profiles')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : linked.length === 0 ? (
        <EmptyState
          icon={Swords}
          title={t('scoping.cycleTabs.noProfiles', 'No attacker profiles chosen')}
          description={t(
            'scoping.cycleTabs.noProfilesHint',
            'Choose the attackers this cycle assumes: external, with stolen credentials, an insider, a supplier.'
          )}
          card={false}
          className="rounded-lg border border-dashed py-8"
        />
      ) : (
        <ul className="divide-y rounded-lg border">
          {linked.map((p) => (
            <li key={p.id} className="px-4 py-3">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                {p.name}
                {p.is_default && (
                  <Lock
                    className="h-3 w-3 text-muted-foreground"
                    aria-label={t('attackerProfiles.builtIn', 'Built-in profile')}
                  />
                )}
              </p>
              <p className="text-xs text-muted-foreground">
                {profileTypeLabel(p.profile_type, t)}
                {p.description ? `, ${p.description}` : ''}
              </p>
            </li>
          ))}
        </ul>
      )}

      <Dialog open={editing} onOpenChange={(o) => !saving && setEditing(o)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('scoping.cycleTabs.profilesDialogTitle', 'Attacker profiles')}
            </DialogTitle>
            <DialogDescription>
              {t('scoping.cycleTabs.profilesDialogHint', 'Choose the attackers {name} assumes.', {
                name: cycle.name,
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <CharterAttackerProfilesField value={draft} onChange={setDraft} editable />
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(false)} disabled={saving}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={save} disabled={saving}>
              {saving ? t('scoping.cycleTabs.saving', 'Saving…') : t('common.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

/** Close-time verdict on the success criteria, and what the cycle taught about scope. */
export function CycleOutcomeTab({ cycle, onSaved }: { cycle: CtemCycle; onSaved: () => void }) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)
  const canNote = cycle.status === 'review' || cycle.status === 'closed'
  const saved = cycle.charter?.scope_refinement_notes ?? ''

  const save = async () => {
    setSaving(true)
    try {
      await saveScopeRefinement(cycle.id, notes)
      toast.success(t('scoping.cycleTabs.notesSaved', 'Scope refinement notes saved.'))
      setEditing(false)
      onSaved()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('scoping.cycleTabs.notesSaveFailed', 'Failed to save scope refinement notes')
        )
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <DetailSections>
      <DetailSection title={t('scoping.cycleTabs.outcomeTitle', 'Success criteria outcome')}>
        {cycle.charter_evaluation ? (
          <CharterOutcome evaluation={cycle.charter_evaluation} />
        ) : (
          <p className="text-sm text-muted-foreground">
            {t(
              'scoping.cycleTabs.outcomePending',
              'Evaluated when the cycle closes, against the success criteria of the charter.'
            )}
          </p>
        )}
      </DetailSection>
      <DetailSection
        title={t('scoping.cycleTabs.refinement', 'Scope refinement')}
        actions={
          canNote ? (
            <Can permission={Permission.CTEMCyclesWrite}>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setNotes(saved)
                  setEditing(true)
                }}
              >
                <NotebookPen className="me-2 h-4 w-4" />
                {saved
                  ? t('scoping.cycleTabs.editNotes', 'Edit notes')
                  : t('scoping.cycleTabs.addNotes', 'Add notes')}
              </Button>
            </Can>
          ) : undefined
        }
      >
        {saved ? (
          <p className="text-sm whitespace-pre-wrap">{saved}</p>
        ) : (
          <p className="text-sm text-muted-foreground">
            {canNote
              ? t(
                  'scoping.cycleTabs.notesPrompt',
                  'What this cycle taught about scope: gaps to add, items to exclude, lessons for the next charter.'
                )
              : t(
                  'scoping.cycleTabs.notesLater',
                  'Recorded at review and close. The next cycle is created with them in view.'
                )}
          </p>
        )}
      </DetailSection>

      <Dialog open={editing} onOpenChange={(o) => !saving && setEditing(o)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('scoping.cycleTabs.notesDialogTitle', 'Scope refinement and lessons')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'scoping.cycleTabs.notesDialogHint',
                'What {name} taught about scope. Shown when the next cycle is created.',
                { name: cycle.name }
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-2">
              <Label htmlFor="scope-notes">{t('scoping.cycleTabs.notes', 'Notes')}</Label>
              <Textarea
                id="scope-notes"
                rows={6}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder={t(
                  'scoping.cycleTabs.notesPlaceholder',
                  'e.g. Add exposed RDP to scope next cycle. The legacy VPN exclusion held up.'
                )}
                disabled={saving}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditing(false)} disabled={saving}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={save} disabled={saving}>
              {saving
                ? t('scoping.cycleTabs.saving', 'Saving…')
                : t('scoping.cycleTabs.saveNotes', 'Save notes')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </DetailSections>
  )
}
