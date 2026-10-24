'use client'

/**
 * The `/` dashboard (api docs/architecture/dashboards.md): one renderer for
 * every stored dashboard, a switcher between the organization's dashboards
 * and the viewer's own, the scope badge, the freshness line with Refresh now
 * and the schedule, and the dashboard's actions. Every figure comes from the
 * dashboard's stored snapshot; the server decides whose numbers they are.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import dynamic from 'next/dynamic'
import { useSWRConfig } from 'swr'
import { Copy, MoreHorizontal, Pencil, SlidersHorizontal, Star, Trash2, X } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Permission, usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import {
  DASHBOARDS_KEY,
  createDashboard,
  deleteDashboard,
  duplicateOrgDashboard,
  setDashboardSchedule,
  setDefaultDashboard,
  setOrgDefaultDashboard,
  updateDashboard,
  useMyDashboards,
  useOrgDashboards,
  useRevalidateAllDashboards,
} from '../api/use-dashboards-api'
import type { Dashboard, DashboardRefreshSchedule } from '../api/dashboards.types'
import { dashboardDataKey, refreshDashboard, useDashboardData } from '../api/widget-data'
import { uniqueDashboardName } from '../lib/unique-name'
import { DEFAULT_TEMPLATE, templateByKey, templateLayout, templateNameKey } from '../templates'
import { DASHBOARD_CHOICE_KEY, parseRef, pickLanding, refKey, type DashboardRef } from '../landing'
import {
  layoutHintFor,
  readLayoutHintDismissed,
  withTemplateWidgets,
  writeLayoutHintDismissed,
} from '../layout-hint'
import { metricNameKey } from '../metrics'
import {
  DashboardFreshness,
  RefreshButton,
  ScheduleMenuItems,
  ScheduleSelect,
} from './dashboard-freshness'
import { DashboardSwitcher } from './dashboard-switcher'
import { DashboardView } from './dashboard-view'

/** Menu rows are 44px tall on a phone (touch target), the kit default from 640px. */
const ITEM = 'min-h-11 sm:min-h-8'

export function DashboardSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4" aria-busy="true">
      {Array.from({ length: 8 }, (_, i) => (
        <Skeleton key={i} className="h-32" />
      ))}
    </div>
  )
}

// The editor (drag and drop kit) loads only when Customize is opened.
const DashboardEditor = dynamic(
  () => import('../editor/dashboard-editor').then((m) => m.DashboardEditor),
  { ssr: false, loading: () => <DashboardSkeleton /> }
)

function readChoice(): DashboardRef | null {
  try {
    return parseRef(window.localStorage.getItem(DASHBOARD_CHOICE_KEY))
  } catch {
    return null
  }
}

function writeChoice(ref: DashboardRef) {
  try {
    window.localStorage.setItem(DASHBOARD_CHOICE_KEY, refKey(ref))
  } catch {
    // A per-viewer convenience only.
  }
}

function clearChoice() {
  try {
    window.localStorage.removeItem(DASHBOARD_CHOICE_KEY)
  } catch {
    // A per-viewer convenience only.
  }
}

export function DashboardHome() {
  const { t } = useTranslation()
  const { canAny, can } = usePermissions()
  const canOrgView = canAny(Permission.DashboardsOrgView, Permission.DashboardsOrgManage)
  const canOrgManage = can(Permission.DashboardsOrgManage)
  const { mutate } = useSWRConfig()
  const revalidate = useRevalidateAllDashboards()

  const mine = useMyDashboards()
  const org = useOrgDashboards(canOrgView)
  const personal = useMemo(() => mine.data?.data ?? [], [mine.data])
  const organization = useMemo(
    () => (canOrgView ? (org.data?.data ?? []) : undefined),
    [canOrgView, org.data]
  )
  const listsLoading = mine.isLoading || (canOrgView && org.isLoading)

  const [chosen, setChosen] = useState<DashboardRef | null>(null)
  const [customizing, setCustomizing] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<Dashboard | null>(null)

  useEffect(() => {
    if (chosen === null) setChosen(readChoice())
  }, [chosen])

  // A person with no dashboard at all (none of their own, none from the
  // organization) gets a personal copy of the default template, computed in
  // their own scope. Created once; a failure leaves the empty state.
  const seeding = useRef(false)
  const [seeded, setSeeded] = useState<string | null>(null)
  const [seedFailed, setSeedFailed] = useState(false)
  // A failed list read is not "nothing": the organization may have
  // dashboards for the viewer, so no copy is made.
  const nothing =
    !listsLoading &&
    !mine.error &&
    !(canOrgView && org.error) &&
    personal.length === 0 &&
    (organization ?? []).length === 0
  useEffect(() => {
    if (!nothing || seeding.current) return
    seeding.current = true
    const tpl = templateByKey(DEFAULT_TEMPLATE)
    const name = t(templateNameKey(tpl.key), tpl.key)
    createDashboard({ name, columns: tpl.columns, layout: templateLayout(tpl) })
      .then(async (d) => {
        setSeeded(name)
        // The new dashboard is the whole list: no second request for it.
        await mutate(DASHBOARDS_KEY, { data: [d] }, { revalidate: false })
        setChosen({ kind: 'personal', id: d.id })
        writeChoice({ kind: 'personal', id: d.id })
      })
      .catch(() => setSeedFailed(true))
  }, [nothing, mutate, t])

  const active = useMemo(
    () => (listsLoading ? null : pickLanding(personal, organization ?? [], chosen)),
    [listsLoading, personal, organization, chosen]
  )
  const dashboard =
    active &&
    (active.kind === 'personal' ? personal : (organization ?? [])).find((d) => d.id === active.id)

  // `/?customize=1` (from the dashboards list) opens straight in customize mode.
  const startCustomizing = useSearchParams()?.get('customize') === '1'
  const customizeStarted = useRef(false)
  useEffect(() => {
    if (!startCustomizing || customizeStarted.current || !dashboard || !active) return
    customizeStarted.current = true
    if (active.kind === 'personal' || canOrgManage) setCustomizing(true)
  }, [startCustomizing, dashboard, active, canOrgManage])

  const data = useDashboardData(active?.kind ?? 'personal', active?.id ?? null)

  const choose = useCallback((ref: DashboardRef) => {
    setChosen(ref)
    setCustomizing(false)
    writeChoice(ref)
  }, [])

  // The offer on a personal copy of a template that has gained widgets since
  // the copy was made. Nothing changes until the viewer chooses.
  const [hintDismissed, setHintDismissed] = useState(true)
  useEffect(() => setHintDismissed(readLayoutHintDismissed()), [])
  const [hintBusy, setHintBusy] = useState(false)
  const layoutHint =
    !hintDismissed && !seeded && active?.kind === 'personal'
      ? layoutHintFor(dashboard ? { ...dashboard, kind: 'personal' } : undefined)
      : null
  const dismissHint = () => {
    writeLayoutHintDismissed()
    setHintDismissed(true)
  }
  const addTemplateWidgets = async () => {
    if (!dashboard || !layoutHint) return
    setHintBusy(true)
    try {
      await updateDashboard(dashboard.id, {
        name: dashboard.name,
        description: dashboard.description,
        columns: dashboard.columns,
        layout: withTemplateWidgets(
          dashboard.layout ?? [],
          templateByKey(layoutHint.template),
          layoutHint.missing
        ),
      })
      dismissHint()
      await Promise.all([revalidate(), data.mutate()])
      toast.success(
        t('dashboards.layoutHint.added', 'The new widgets were added to this dashboard')
      )
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setHintBusy(false)
    }
  }
  const switchToTemplate = async () => {
    if (!layoutHint) return
    setHintBusy(true)
    try {
      const tpl = templateByKey(layoutHint.template)
      const name = t(templateNameKey(tpl.key), tpl.key)
      // Names are unique per person: the copy the hint is shown on often has
      // the template's own name.
      const base = t('dashboards.layoutHint.copyName', '{name} (new layout)', { name })
      const copyName = uniqueDashboardName(
        name,
        personal.map((d) => d.name),
        base
      )
      const d = await createDashboard({
        name: copyName,
        columns: tpl.columns,
        layout: templateLayout(tpl),
      })
      dismissHint()
      await revalidate()
      choose({ kind: 'personal', id: d.id })
      toast.success(
        t(
          'dashboards.layoutHint.switched',
          'The new {name} layout was added; your dashboard is kept',
          {
            name,
          }
        )
      )
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setHintBusy(false)
    }
  }
  const hintNames = layoutHint
    ? layoutHint.missing.slice(0, 4).map((m) => t(metricNameKey(m), m))
    : []
  const hintMore = layoutHint ? layoutHint.missing.length - hintNames.length : 0

  const refresh = async () => {
    if (!active) return
    const fresh = await refreshDashboard(active.kind, active.id)
    await mutate(dashboardDataKey(active.kind, active.id), fresh, { revalidate: false })
  }

  const schedule = async (s: DashboardRefreshSchedule) => {
    if (!active) return
    await setDashboardSchedule(active.kind, active.id, s)
    await Promise.all([revalidate(), data.mutate()])
  }

  // The new default shows in the switcher and menu: no success toast.
  const setDefault = async (d: Dashboard, org: boolean) => {
    try {
      await (org ? setOrgDefaultDashboard(d.id) : setDefaultDashboard(d.id))
      // A stored last choice outranks the default on the next visit, so the
      // new personal default would never take effect.
      if (!org) {
        clearChoice()
        setChosen(null)
      }
      await revalidate()
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  const duplicate = async (id: string) => {
    try {
      const copy = await duplicateOrgDashboard(id)
      await revalidate()
      choose({ kind: 'personal', id: copy.id })
      toast.success(t('dashboards.actions.duplicated', 'A copy was added to your dashboards'))
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  const remove = async (d: Dashboard) => {
    try {
      await deleteDashboard(d.id)
      await revalidate()
      setPendingDelete(null)
      setChosen(null)
      toast.success(t('confirm.dashboard.deleted', 'Dashboard "{name}" deleted', { name: d.name }))
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  const isOrg = active?.kind === 'organization'
  const canSchedule = !!dashboard && (isOrg ? canOrgManage : true)
  // An organization dashboard is edited only by those who may manage them.
  const canCustomize = !!dashboard && (isOrg ? canOrgManage : true)
  const isDefault = dashboard ? (isOrg ? dashboard.is_org_default : dashboard.is_default) : false

  return (
    <Main>
      <PageStack>
        {/* Phone: the switcher fills row 1 beside icon-only Refresh and More;
            Customize and the schedule move into More. From 640px one toolbar
            row: switcher, Customize, schedule, Refresh now, More. */}
        <PageHeader
          title={dashboard?.name ?? t('dashboards.title', 'Dashboard')}
          description={
            <span className="max-sm:hidden">
              {dashboard?.description ||
                t(
                  'dashboards.description',
                  'How exposed you are, whether it is getting better, and what to do next.'
                )}
            </span>
          }
          actionsClassName="basis-full sm:basis-auto"
        >
          <div
            className="flex w-full min-w-0 flex-nowrap items-center gap-2 sm:w-auto"
            data-testid="dashboard-toolbar"
          >
            <DashboardSwitcher
              personal={personal}
              organization={organization}
              active={active}
              onChoose={choose}
              className="h-11 min-w-0 max-w-none flex-1 justify-start sm:h-8 sm:max-w-[16rem] sm:flex-none"
            />
            {canCustomize && (
              <Button
                variant="outline"
                size="sm"
                className="hidden sm:inline-flex"
                onClick={() => setCustomizing(true)}
                disabled={customizing}
              >
                <SlidersHorizontal className="me-2 h-4 w-4" aria-hidden />
                {t('dashboards.actions.customize', 'Customize')}
              </Button>
            )}
            {canSchedule && !customizing && (
              <ScheduleSelect
                schedule={dashboard?.refresh_schedule}
                onSchedule={schedule}
                className="hidden sm:flex"
              />
            )}
            {dashboard && !customizing && <RefreshButton onRefresh={refresh} />}
            {dashboard && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-11 w-11 shrink-0 sm:h-8 sm:w-8"
                    aria-label={t('dashboards.actions.more', 'More dashboard actions')}
                  >
                    <MoreHorizontal className="h-4 w-4" aria-hidden />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-64">
                  {canCustomize && (
                    <DropdownMenuItem
                      className={cn(ITEM, 'sm:hidden')}
                      onSelect={() => setCustomizing(true)}
                      disabled={customizing}
                    >
                      <SlidersHorizontal className="me-2 h-4 w-4" aria-hidden />
                      {t('dashboards.actions.customize', 'Customize')}
                    </DropdownMenuItem>
                  )}
                  {isOrg && (
                    <DropdownMenuItem className={ITEM} onSelect={() => duplicate(dashboard.id)}>
                      <Copy className="me-2 h-4 w-4" aria-hidden />
                      {t('dashboards.actions.duplicate', 'Duplicate to mine')}
                    </DropdownMenuItem>
                  )}
                  {!isDefault && (!isOrg || canOrgManage) && (
                    <DropdownMenuItem
                      className={ITEM}
                      onSelect={() => setDefault(dashboard, isOrg)}
                    >
                      <Star className="me-2 h-4 w-4" aria-hidden />
                      {isOrg
                        ? t('dashboards.actions.setOrgDefault', 'Set as organization default')
                        : t('dashboards.actions.setDefault', 'Set as my default')}
                    </DropdownMenuItem>
                  )}
                  {(!isOrg || canOrgManage) && (
                    <DropdownMenuItem className={ITEM} asChild>
                      <Link href="/dashboards">
                        <Pencil className="me-2 h-4 w-4" aria-hidden />
                        {t('dashboards.actions.edit', 'Edit details')}
                      </Link>
                    </DropdownMenuItem>
                  )}
                  {canSchedule && !customizing && (
                    <div className="sm:hidden">
                      <DropdownMenuSeparator />
                      <ScheduleMenuItems
                        schedule={dashboard.refresh_schedule}
                        onSchedule={schedule}
                      />
                    </div>
                  )}
                  {!isOrg && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className={cn(ITEM, 'text-destructive focus:text-destructive')}
                        onSelect={() => setPendingDelete(dashboard)}
                      >
                        <Trash2 className="me-2 h-4 w-4" aria-hidden />
                        {t('dashboards.actions.delete', 'Delete')}
                      </DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </PageHeader>
        {dashboard && active && !customizing && (
          <DashboardFreshness kind={active.kind} data={data.data} />
        )}

        {listsLoading ? (
          <DashboardSkeleton />
        ) : !dashboard || !active ? (
          seedFailed || !nothing ? (
            <div className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
              {t('dashboards.view.none', 'You have no dashboards yet.')}{' '}
              <Link href="/dashboards" className="font-medium text-foreground underline">
                {t('dashboards.switcher.new', 'New dashboard')}
              </Link>
            </div>
          ) : (
            <DashboardSkeleton />
          )
        ) : customizing ? (
          <DashboardEditor
            dashboard={dashboard}
            kind={active.kind}
            data={data.data}
            onExit={(saved) => {
              setCustomizing(false)
              if (saved) void Promise.all([revalidate(), data.mutate()])
            }}
          />
        ) : (
          <>
            {seeded && (
              <p
                className="rounded-md border bg-muted/40 px-3 py-2 text-sm text-muted-foreground"
                role="status"
              >
                {t(
                  'dashboards.view.seeded',
                  'This is the {name} layout, computed for your own access.',
                  { name: seeded }
                )}{' '}
                <button
                  type="button"
                  className="font-medium text-foreground underline"
                  onClick={() => setCustomizing(true)}
                >
                  {t('dashboards.actions.customize', 'Customize')}
                </button>{' '}
                <Link href="/dashboards" className="font-medium text-foreground underline">
                  {t('dashboards.view.chooseAnother', 'Choose another')}
                </Link>
              </p>
            )}
            {layoutHint && (
              <div
                className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm"
                role="status"
                data-testid="layout-hint"
              >
                <span className="min-w-0 flex-1 basis-60 text-muted-foreground">
                  {t('dashboards.layoutHint.text', 'New on the {template} layout: {names}.', {
                    template: t(templateNameKey(layoutHint.template), layoutHint.template),
                    names:
                      hintNames.join(', ') +
                      (hintMore > 0
                        ? ` ${t('dashboards.layoutHint.more', 'and {n} more', { n: hintMore })}`
                        : ''),
                  })}
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={hintBusy}
                  onClick={addTemplateWidgets}
                >
                  {t('dashboards.layoutHint.add', 'Add them to this dashboard')}
                </Button>
                <Button size="sm" variant="ghost" disabled={hintBusy} onClick={switchToTemplate}>
                  {t('dashboards.layoutHint.switch', 'Switch to the new layout')}
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-8 w-8"
                  onClick={dismissHint}
                  aria-label={t('dashboards.layoutHint.dismiss', 'Dismiss')}
                >
                  <X className="h-4 w-4" aria-hidden />
                </Button>
              </div>
            )}
            <DashboardView
              dashboard={dashboard}
              data={data.data}
              loading={data.isLoading}
              failed={!!data.error && !data.data}
              onRetry={() => data.mutate()}
            />
          </>
        )}
      </PageStack>
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        destructive
        title={t('confirm.dashboard.deleteTitle', 'Delete dashboard "{name}"?', {
          name: pendingDelete?.name ?? '',
        })}
        desc={t(
          'confirm.dashboard.deleteDescPersonal',
          'Your dashboard and its layout are deleted. Copies you shared and your data are not affected. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        handleConfirm={() => (pendingDelete ? remove(pendingDelete) : undefined)}
      />
    </Main>
  )
}
