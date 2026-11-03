'use client'

/**
 * Settings > Modules: turn features on or off for this organization.
 * Design: research/394 §4 (one grouped list, dependencies written out, an
 * impact preview before saving, locks with their reason).
 */
import { useCallback, useMemo, useState } from 'react'
import { AlertCircle, AlertTriangle, RotateCcw, SearchX } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  EmptyState,
  FilterSelect,
  ListToolbar,
  PageHeader,
  PageStack,
  ReadOnlyNotice,
  SettingsSaveBar,
  SettingsSection,
} from '@/features/shared'
import { useTenant } from '@/context/tenant-provider'
import { useBootstrapContext } from '@/context/bootstrap-provider'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlFilter } from '@/hooks/use-url-param'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { useFormatList } from '@/lib/format-list'
import {
  Can,
  Permission,
  isHiddenReleaseStatus,
  useCanMutate,
  useHasPermission,
} from '@/lib/permissions'
import {
  useModuleDependencyGraph,
  useModuleRealtimeInvalidation,
  useResetTenantModules,
  useTenantModules,
  useUpdateTenantModules,
} from '@/features/organization/api/use-tenant-modules'
import type {
  ModuleToggle,
  TenantModule,
  ToggleIssue,
} from '@/features/organization/api/use-tenant-modules'
import {
  applyToggle,
  buildDependencyIndex,
  computePlan,
  unavailableRequirements,
  type PlanOptions,
} from '@/features/organization/lib/module-plan'
import {
  ModuleImpactDialog,
  ModuleRow,
  ModulesLastChange,
  useModuleText,
  type ModuleChange,
  type ModuleLock,
} from '@/features/organization/components/module-settings'

/** The 400 body of PATCH /settings/modules when the dependency check refuses. */
interface ModuleDependencyErrorDetails {
  module_id: string
  module_name: string
  action: 'enable' | 'disable'
  blockers?: ToggleIssue[]
  required?: ToggleIssue[]
}

/**
 * Module groups, in order: the exposure-management phases, then the
 * supporting groups. Each folds one or more registry categories; a category
 * not listed lands in "Other", so no module is ever dropped.
 */
const GROUPS: { key: string; label: string; categories: string[] }[] = [
  { key: 'scoping', label: 'Scoping', categories: ['scoping'] },
  { key: 'discovery', label: 'Discovery', categories: ['discovery'] },
  { key: 'prioritization', label: 'Prioritization', categories: ['prioritization'] },
  { key: 'validation', label: 'Validation', categories: ['validation'] },
  { key: 'mobilization', label: 'Mobilization', categories: ['mobilization'] },
  { key: 'insights', label: 'Reporting and compliance', categories: ['insights', 'compliance'] },
  { key: 'operations', label: 'Operations and data', categories: ['operations', 'data'] },
  { key: 'settings', label: 'Scanning', categories: ['settings', 'platform'] },
]

type StateFilter = 'on' | 'off' | 'unavailable'
const STATE_FILTERS: StateFilter[] = ['on', 'off', 'unavailable']

const PATCH_ROUTE = 'PATCH /api/v1/tenants/{tenant}/settings/modules' as const

export default function ModuleManagementPage() {
  const { t } = useTranslation()
  const text = useModuleText()
  const formatList = useFormatList()
  const pageTitle = t('settings.item.modules', 'Modules')
  const pageDescription = t(
    'settings.modules.pageDescription',
    'Turn features on or off for this organization. Turning one off hides its pages and stops its jobs; its data is kept and comes back when you turn it on.'
  )
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id

  const { modules, isLoading, error, mutate } = useTenantModules(tenantId)
  const { updateModules, isUpdating } = useUpdateTenantModules(tenantId)
  const { resetModules, isResetting } = useResetTenantModules(tenantId)
  const { edges } = useModuleDependencyGraph(tenantId)
  const { refreshModules, data: bootstrapData } = useBootstrapContext()
  // Modules in read-only grace (made unavailable recently), with its end.
  const readOnlyUntil = bootstrapData?.modules?.read_only_modules
  // Another admin's change reaches this page within a second.
  useModuleRealtimeInvalidation(tenantId)

  const canEdit = useCanMutate(PATCH_ROUTE)
  const canReadAudit = useHasPermission(Permission.AuditRead)

  const [query, setQuery] = useUrlFilter('q', '')
  const [stateParam, setStateParam] = useUrlFilter('state', '')
  const stateFilter = STATE_FILTERS.includes(stateParam as StateFilter)
    ? (stateParam as StateFilter)
    : ''

  const [pending, setPending] = useState<Record<string, boolean>>({})
  const [showImpact, setShowImpact] = useState(false)
  const [showReset, setShowReset] = useState(false)
  const [depConflict, setDepConflict] = useState<ModuleDependencyErrorDetails | null>(null)

  const visibleModules = useMemo(
    () =>
      modules
        .filter((m) => !isHiddenReleaseStatus(m.release_status))
        .sort((a, b) => a.display_order - b.display_order),
    [modules]
  )
  const byId = useMemo(() => {
    const map: Record<string, TenantModule> = {}
    for (const m of visibleModules) map[m.id] = m
    return map
  }, [visibleModules])
  // API (English) names, the fallback for module ids the catalog lacks.
  const apiNames = useMemo(() => {
    const map: Record<string, string> = {}
    for (const m of modules) {
      map[m.id] = m.name
      for (const s of m.sub_modules ?? []) map[s.id] = s.name
    }
    return map
  }, [modules])
  const saved = useMemo(() => {
    const map: Record<string, boolean> = {}
    for (const m of modules) {
      map[m.id] = m.is_enabled
      for (const s of m.sub_modules ?? []) map[s.id] = s.is_enabled
    }
    return map
  }, [modules])

  const subIds = useMemo(
    () => new Set(modules.flatMap((m) => (m.sub_modules ?? []).map((s) => s.id))),
    [modules]
  )
  const index = useMemo(() => buildDependencyIndex(edges), [edges])

  const lockOf = useCallback(
    (m: TenantModule): ModuleLock | undefined => {
      if (m.is_core) return { kind: 'always_on' }
      if (m.release_status === 'coming_soon') return { kind: 'coming_soon' }
      if (m.reason === 'disabled_by_platform') return { kind: 'platform' }
      const until = readOnlyUntil?.[m.id]
      if (until && (m.reason === 'read_only_grace' || m.entitled === false)) {
        return { kind: 'read_only', until }
      }
      if (
        m.entitled === false ||
        m.reason === 'not_entitled' ||
        m.reason === 'unavailable' ||
        m.reason === 'read_only_grace'
      ) {
        return { kind: 'not_entitled' }
      }
      return undefined
    },
    [readOnlyUntil]
  )

  const planOpts = useMemo<PlanOptions>(
    () => ({
      // Modules this page does not list are not changed from here.
      isCore: (id) => (byId[id] ? byId[id].is_core : !subIds.has(id)),
      canEnable: (id) => {
        const m = byId[id]
        return !!m && !lockOf(m)
      },
    }),
    [byId, subIds, lockOf]
  )

  const plan = useMemo(
    () => computePlan(saved, pending, index, planOpts),
    [saved, pending, index, planOpts]
  )
  const effective = useCallback(
    (id: string) => (id in plan.changes ? plan.changes[id] : !!saved[id]),
    [plan, saved]
  )

  const rowLock = useCallback(
    (m: TenantModule): ModuleLock | undefined => {
      const own = lockOf(m)
      if (own) return own
      if (saved[m.id]) return undefined
      const missing = unavailableRequirements(m.id, saved, index, planOpts)
      return missing.length ? { kind: 'needs_unavailable', modules: missing } : undefined
    },
    [lockOf, saved, index, planOpts]
  )

  const changeOf = useCallback(
    (id: string): ModuleChange | undefined => {
      if (!(id in plan.changes)) return undefined
      if (plan.offWith[id]) return { kind: 'off_with', because: plan.offWith[id] }
      if (plan.onWith[id]) return { kind: 'on_with', because: plan.onWith[id] }
      return { kind: plan.changes[id] ? 'on' : 'off' }
    },
    [plan]
  )

  // Requirements and dependents worth naming: core modules are always on.
  const listed = useCallback(
    (ids: string[] | undefined) => (ids ?? []).filter((id) => byId[id] && !byId[id].is_core),
    [byId]
  )

  const { coreModules, featureModules } = useMemo(() => {
    const core: TenantModule[] = []
    const features: TenantModule[] = []
    for (const m of visibleModules) (m.is_core ? core : features).push(m)
    return { coreModules: core, featureModules: features }
  }, [visibleModules])

  const needle = query.trim().toLocaleLowerCase()
  const matchesQuery = useCallback(
    (m: TenantModule) => {
      if (!needle) return true
      return [m.id, m.name, text.name(m.id, m.name), text.description(m.id, m.description)]
        .join(' ')
        .toLocaleLowerCase()
        .includes(needle)
    },
    [needle, text]
  )
  const stateOf = useCallback(
    (m: TenantModule): StateFilter => (lockOf(m) ? 'unavailable' : effective(m.id) ? 'on' : 'off'),
    [lockOf, effective]
  )

  const groups = useMemo(() => {
    const catToGroup: Record<string, string> = {}
    for (const g of GROUPS) for (const c of g.categories) catToGroup[c] = g.key
    const byKey: Record<string, TenantModule[]> = {}
    for (const m of featureModules) (byKey[catToGroup[m.category] ?? 'other'] ||= []).push(m)
    const order = [...GROUPS, { key: 'other', label: 'Other', categories: [] }]
    return order
      .filter((g) => byKey[g.key]?.length)
      .map((g) => {
        const all = byKey[g.key]
        return {
          key: g.key,
          label: t(`settings.modules.phase.${g.key}`, g.label),
          total: all.length,
          on: all.filter((m) => effective(m.id)).length,
          shown: all.filter((m) => matchesQuery(m) && (!stateFilter || stateOf(m) === stateFilter)),
        }
      })
  }, [featureModules, effective, matchesQuery, stateFilter, stateOf, t])

  const stateCounts = useMemo(() => {
    const c: Record<StateFilter, number> = { on: 0, off: 0, unavailable: 0 }
    for (const m of featureModules) c[stateOf(m)]++
    return c
  }, [featureModules, stateOf])
  const featureOn = featureModules.filter((m) => effective(m.id)).length

  // Core modules shown on the "Always on" line, and core modules with
  // sub-features of their own that can be switched (listed as rows).
  const coreShown =
    stateFilter === 'off' || stateFilter === 'unavailable' ? [] : coreModules.filter(matchesQuery)
  const coreWithSubs = coreShown.filter((m) =>
    (m.sub_modules ?? []).some((s) => !isHiddenReleaseStatus(s.release_status))
  )
  const shownCount = groups.reduce((n, g) => n + g.shown.length, 0) + coreShown.length

  const changeEntries = Object.entries(plan.changes)
  const toEnable = changeEntries.filter(([, v]) => v).length
  const toDisable = changeEntries.length - toEnable
  const isDirty = changeEntries.length > 0

  const onToggle = useCallback(
    (id: string, next: boolean) => setPending((prev) => applyToggle(prev, saved, id, next, index)),
    [saved, index]
  )

  const runSave = useCallback(
    async (changes: Record<string, boolean>) => {
      const toggles: ModuleToggle[] = Object.entries(changes).map(([module_id, is_enabled]) => ({
        module_id,
        is_enabled,
      }))
      try {
        const result = await updateModules({ modules: toggles })
        if (result) await mutate(result, false)
        setPending({})
        setShowImpact(false)
        await refreshModules()
        toast.success(t('settings.modules.updated', 'Modules updated'))
        for (const w of result?.warnings ?? []) {
          toast.warning(
            t('settings.modules.willDegrade', '{name} works with less', {
              name: text.name(w.module_id, w.name),
            }),
            { description: w.reason, duration: 6000 }
          )
        }
      } catch (err) {
        setShowImpact(false)
        if (
          err instanceof ApiClientError &&
          err.code === 'module_dependency_violation' &&
          err.details
        ) {
          setDepConflict(err.details as unknown as ModuleDependencyErrorDetails)
          return
        }
        toast.error(getErrorMessage(err))
      }
    },
    [updateModules, mutate, refreshModules, t, text]
  )

  const handleSave = useCallback(() => {
    if (!isDirty) return
    const needsPreview = toDisable > 0 || Object.keys(plan.onWith).length > 0
    if (needsPreview) setShowImpact(true)
    else void runSave(plan.changes)
  }, [isDirty, toDisable, plan, runSave])

  // Fallback when the API still refuses (a graph newer than the page's).
  const handleConflictResolve = useCallback(async () => {
    if (!depConflict) return
    const merged = { ...plan.changes }
    if (depConflict.action === 'disable') {
      for (const b of depConflict.blockers ?? []) merged[b.module_id] = false
    } else {
      for (const r of depConflict.required ?? []) merged[r.module_id] = true
    }
    setDepConflict(null)
    await runSave(merged)
  }, [depConflict, plan, runSave])

  const handleReset = useCallback(async () => {
    try {
      const result = await resetModules()
      if (result) await mutate(result, false)
      setPending({})
      setShowReset(false)
      await refreshModules()
      toast.success(t('settings.modules.resetDone', 'Modules reset to the defaults'))
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }, [resetModules, mutate, refreshModules, t])

  if (error && !modules.length) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={pageTitle} description={pageDescription} />
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>{t('settings.modules.loadFailed', 'Failed to load modules')}</AlertTitle>
            <AlertDescription>
              <p>
                {getErrorMessage(
                  error,
                  t('settings.modules.requestFailed', 'The modules request failed.')
                )}
              </p>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                {t('common.retry', 'Retry')}
              </Button>
            </AlertDescription>
          </Alert>
        </PageStack>
      </Main>
    )
  }

  if (isLoading) {
    return (
      <Main>
        <PageStack>
          <PageHeader title={pageTitle} description={pageDescription} />
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-32 w-full rounded-xl" />
          ))}
        </PageStack>
      </Main>
    )
  }

  const conflictNames = (issues: ToggleIssue[] | undefined) =>
    formatList((issues ?? []).map((i) => text.name(i.module_id, i.name)))
  const conflictName = depConflict ? text.name(depConflict.module_id, depConflict.module_name) : ''
  const conflictCount =
    depConflict?.action === 'disable'
      ? (depConflict.blockers?.length ?? 0)
      : (depConflict?.required?.length ?? 0)

  return (
    <Main>
      <PageStack>
        <PageHeader title={pageTitle} description={pageDescription}>
          <Can route="POST /api/v1/tenants/{tenant}/settings/modules/reset">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowReset(true)}
              disabled={isResetting}
            >
              <RotateCcw className="h-4 w-4" />
              {t('settings.modules.reset', 'Reset to defaults')}
            </Button>
          </Can>
        </PageHeader>

        {!canEdit && (
          <ReadOnlyNotice
            reason={t(
              'settings.modules.readOnly',
              'You can see which modules are on. Only administrators can change them.'
            )}
          />
        )}

        <ListToolbar
          search={{
            value: query,
            onChange: setQuery,
            placeholder: t('settings.modules.searchPlaceholder', 'Search modules…'),
            label: t('settings.modules.searchLabel', 'Search modules'),
          }}
          start={
            <FilterSelect<StateFilter>
              label={t('settings.modules.filter.label', 'Show')}
              value={stateFilter}
              onChange={(v) => setStateParam(v)}
              allLabel={t('settings.modules.filter.all', 'All')}
              allCount={featureModules.length}
              options={[
                {
                  value: 'on',
                  label: t('settings.modules.filter.on', 'On'),
                  count: stateCounts.on,
                },
                {
                  value: 'off',
                  label: t('settings.modules.filter.off', 'Off'),
                  count: stateCounts.off,
                },
                {
                  value: 'unavailable',
                  label: t('settings.modules.filter.unavailable', 'Unavailable'),
                  count: stateCounts.unavailable,
                },
              ]}
            />
          }
          end={
            <span className="text-sm tabular-nums text-muted-foreground" role="status">
              {t('settings.modules.onCount', '{on} of {total} on', {
                on: featureOn,
                total: featureModules.length,
              })}
            </span>
          }
        />

        {coreShown.length > 0 && (
          <SettingsSection
            id="modules-always-on"
            title={t('settings.modules.alwaysOnTitle', 'Always on')}
            description={formatList(coreShown.map((m) => text.name(m.id, m.name)))}
          >
            {coreWithSubs.length > 0 && (
              <ul className="divide-y rounded-xl border">
                {coreWithSubs.map((m) => (
                  <ModuleRow
                    key={m.id}
                    id={m.id}
                    apiName={m.name}
                    apiDescription={m.description}
                    enabled
                    lock={{ kind: 'always_on' }}
                    readOnly={!canEdit}
                    busy={isUpdating}
                    apiNames={apiNames}
                    subModules={m.sub_modules}
                    subEnabled={Object.fromEntries(
                      (m.sub_modules ?? []).map((s) => [s.id, effective(s.id)])
                    )}
                    onToggle={onToggle}
                  />
                ))}
              </ul>
            )}
          </SettingsSection>
        )}

        {groups
          .filter((g) => g.shown.length > 0)
          .map((g) => (
            <SettingsSection
              key={g.key}
              id={`modules-${g.key}`}
              title={g.label}
              actions={
                <span className="text-sm tabular-nums text-muted-foreground">
                  {t('settings.modules.onCount', '{on} of {total} on', {
                    on: g.on,
                    total: g.total,
                  })}
                </span>
              }
            >
              <ul className="divide-y rounded-xl border">
                {g.shown.map((m) => (
                  <ModuleRow
                    key={m.id}
                    id={m.id}
                    apiName={m.name}
                    apiDescription={m.description}
                    beta={m.release_status === 'beta'}
                    enabled={effective(m.id)}
                    change={changeOf(m.id)}
                    lock={rowLock(m)}
                    readOnly={!canEdit}
                    busy={isUpdating}
                    requires={listed(index.requires[m.id])}
                    requiredBy={listed(index.requiredBy[m.id])}
                    apiNames={apiNames}
                    health={m.health}
                    healthDetail={m.health_detail}
                    subModules={m.sub_modules}
                    subEnabled={Object.fromEntries(
                      (m.sub_modules ?? []).map((s) => [s.id, effective(s.id)])
                    )}
                    onToggle={onToggle}
                  />
                ))}
              </ul>
            </SettingsSection>
          ))}

        {shownCount === 0 && (
          <EmptyState
            icon={SearchX}
            title={t('settings.modules.noMatch', 'No modules match')}
            description={t(
              'settings.modules.noMatchHint',
              'Try another word, or show all modules.'
            )}
            action={
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setQuery('')
                  setStateParam('')
                }}
              >
                {t('settings.modules.clearFilters', 'Show all modules')}
              </Button>
            }
          />
        )}

        {canReadAudit && <ModulesLastChange />}

        {canEdit && (
          <SettingsSaveBar
            dirty={isDirty}
            saving={isUpdating}
            onSave={handleSave}
            onDiscard={() => setPending({})}
            summary={
              formatList([
                toEnable > 0 &&
                  t('settings.modules.toEnable', '{count} to turn on', { count: toEnable }),
                toDisable > 0 &&
                  t('settings.modules.toDisable', '{count} to turn off', { count: toDisable }),
              ]) || undefined
            }
          />
        )}

        <ModuleImpactDialog
          open={showImpact}
          onOpenChange={setShowImpact}
          plan={plan}
          apiNames={apiNames}
          saving={isUpdating}
          onConfirm={() => void runSave(plan.changes)}
        />

        <ConfirmDialog
          open={!!depConflict}
          onOpenChange={(open) => !open && setDepConflict(null)}
          title={
            <span className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-muted-foreground" />
              {depConflict?.action === 'disable'
                ? t('settings.modules.cannotDisable', '{name} cannot turn off alone', {
                    name: conflictName,
                  })
                : t('settings.modules.cannotEnable', '{name} cannot turn on alone', {
                    name: conflictName,
                  })}
            </span>
          }
          desc={
            depConflict?.action === 'disable'
              ? t(
                  'settings.modules.blockedBody',
                  '{names} {count, plural, one {needs} other {need}} {name}. Turn them off together, or cancel.',
                  {
                    names: conflictNames(depConflict.blockers),
                    count: conflictCount,
                    name: conflictName,
                  }
                )
              : t(
                  'settings.modules.requiredBody',
                  '{name} needs {names}. Turn them on together, or cancel.',
                  { names: conflictNames(depConflict?.required), name: conflictName }
                )
          }
          confirmText={
            depConflict?.action === 'disable'
              ? t('confirm.modules.offTogether', 'Turn off all {count} together', {
                  count: conflictCount + 1,
                })
              : t('confirm.modules.onTogether', 'Turn on all {count} together', {
                  count: conflictCount + 1,
                })
          }
          destructive={depConflict?.action === 'disable'}
          isLoading={isUpdating}
          handleConfirm={handleConflictResolve}
        />

        <ConfirmDialog
          open={showReset}
          onOpenChange={setShowReset}
          title={t('confirm.modules.resetTitle', 'Reset modules to the defaults?')}
          desc={t(
            'confirm.modules.resetDesc',
            'Every module available to this organization turns on again, and the choices made on this page are cleared. This cannot be undone.'
          )}
          confirmText={t('confirm.modules.reset', 'Reset to defaults')}
          destructive
          isLoading={isResetting}
          handleConfirm={() => void handleReset()}
        />
      </PageStack>
    </Main>
  )
}
