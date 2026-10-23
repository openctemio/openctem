'use client'

/**
 * The `/` dashboard (api docs/architecture/dashboards.md): one renderer for
 * every stored dashboard, a switcher between the organization's dashboards
 * and the viewer's own, the scope badge, the freshness line with Refresh now
 * and the schedule, and the dashboard's actions. Every figure comes from the
 * dashboard's stored snapshot; the server decides whose numbers they are.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import { PageHeader } from '@/features/shared'
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
import { DEFAULT_TEMPLATE, templateByKey, templateLayout, templateNameKey } from '../templates'
import { DASHBOARD_CHOICE_KEY, parseRef, pickLanding, refKey, type DashboardRef } from '../landing'
import {
  needsCtemHint,
  readCtemHintDismissed,
  withCtemLoop,
  writeCtemHintDismissed,
} from '../ctem-hint'
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

  const data = useDashboardData(active?.kind ?? 'personal', active?.id ?? null)

  const choose = useCallback((ref: DashboardRef) => {
    setChosen(ref)
    setCustomizing(false)
    writeChoice(ref)
  }, [])

  // The one-time CTEM offer on an Overview copy made before the template
  // carried the loop. Nothing changes until the viewer chooses.
  const [hintDismissed, setHintDismissed] = useState(true)
  useEffect(() => setHintDismissed(readCtemHintDismissed()), [])
  const [hintBusy, setHintBusy] = useState(false)
  const showCtemHint =
    !hintDismissed &&
    !seeded &&
    active?.kind === 'personal' &&
    needsCtemHint(dashboard ? { ...dashboard, kind: 'personal' } : undefined)
  const dismissHint = () => {
    writeCtemHintDismissed()
    setHintDismissed(true)
  }
  const addCtemLoop = async () => {
    if (!dashboard) return
    setHintBusy(true)
    try {
      await updateDashboard(dashboard.id, {
        name: dashboard.name,
        description: dashboard.description,
        columns: dashboard.columns,
        layout: withCtemLoop(dashboard.layout ?? []),
      })
      dismissHint()
      await Promise.all([revalidate(), data.mutate()])
      toast.success(t('dashboards.ctemHint.added', 'The CTEM loop was added to this dashboard'))
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setHintBusy(false)
    }
  }
  const switchToCtem = async () => {
    setHintBusy(true)
    try {
      const tpl = templateByKey('ctem')
      const d = await createDashboard({
        name: t(templateNameKey(tpl.key), tpl.key),
        columns: tpl.columns,
        layout: templateLayout(tpl),
      })
      dismissHint()
      await revalidate()
      choose({ kind: 'personal', id: d.id })
      toast.success(
        t('dashboards.ctemHint.switched', 'The CTEM dashboard was added; your Overview is kept')
      )
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setHintBusy(false)
    }
  }

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

  const run = async (fn: () => Promise<unknown>, done: string) => {
    try {
      await fn()
      await revalidate()
      toast.success(done)
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
  const isDefault = dashboard ? (isOrg ? dashboard.is_org_default : dashboard.is_default) : false

  return (
    <Main>
      <div className="flex flex-col gap-4">
        {/* Phone: the switcher fills row 1 beside icon-only Refresh and More;
            Customize and the schedule move into More. From 640px one toolbar
            row: switcher, Customize, schedule, Refresh now, More. */}
        <PageHeader
          title={dashboard?.name ?? t('dashboards.title', 'Dashboard')}
          description={
            <span className="hidden sm:inline">
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
            {dashboard && !isOrg && (
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
            {dashboard && !customizing && (
              <RefreshButton onRefresh={refresh} disabled={!data.data} />
            )}
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
                  {!isOrg && (
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
                      onSelect={() =>
                        run(
                          () =>
                            isOrg
                              ? setOrgDefaultDashboard(dashboard.id)
                              : setDefaultDashboard(dashboard.id),
                          t('dashboards.actions.defaultSet', 'Default dashboard set')
                        )
                      }
                    >
                      <Star className="me-2 h-4 w-4" aria-hidden />
                      {isOrg
                        ? t('dashboards.actions.setOrgDefault', 'Set as organization default')
                        : t('dashboards.actions.setDefault', 'Set as my default')}
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuItem className={ITEM} asChild>
                    <Link href="/dashboards">
                      <Pencil className="me-2 h-4 w-4" aria-hidden />
                      {t('dashboards.actions.edit', 'Edit details')}
                    </Link>
                  </DropdownMenuItem>
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
                ·{' '}
                <Link href="/dashboards" className="font-medium text-foreground underline">
                  {t('dashboards.view.chooseAnother', 'Choose another')}
                </Link>
              </p>
            )}
            {showCtemHint && (
              <div
                className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm"
                role="status"
                data-testid="ctem-hint"
              >
                <span className="min-w-0 flex-1 text-muted-foreground">
                  {t(
                    'dashboards.ctemHint.text',
                    'The CTEM loop is back: see scoping, discovery, prioritization, validation and mobilization at a glance.'
                  )}
                </span>
                <Button size="sm" variant="outline" disabled={hintBusy} onClick={addCtemLoop}>
                  {t('dashboards.ctemHint.add', 'Add the CTEM loop')}
                </Button>
                <Button size="sm" variant="ghost" disabled={hintBusy} onClick={switchToCtem}>
                  {t('dashboards.ctemHint.switch', 'Switch to the CTEM template')}
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-8 w-8"
                  onClick={dismissHint}
                  aria-label={t('dashboards.ctemHint.dismiss', 'Dismiss')}
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
      </div>
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        destructive
        title={t('confirm.dashboard.deleteTitle', 'Delete dashboard "{name}"?', {
          name: pendingDelete?.name ?? '',
        })}
        desc={t(
          'confirm.dashboard.deleteDesc',
          'The dashboard and its widget layout are deleted for everyone who can see it. Your data is not affected. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        handleConfirm={() => (pendingDelete ? remove(pendingDelete) : undefined)}
      />
    </Main>
  )
}
