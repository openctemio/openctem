'use client'

/**
 * The `/` dashboard (api docs/architecture/dashboards.md): one renderer for
 * every stored dashboard, a switcher between the organization's dashboards
 * and the viewer's own, the scope badge, the freshness line with Refresh now
 * and the schedule, and the dashboard's actions. Every figure comes from the
 * dashboard's stored snapshot; the server decides whose numbers they are.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import dynamic from 'next/dynamic'
import { useSWRConfig } from 'swr'
import { Copy, MoreHorizontal, Pencil, SlidersHorizontal, Star, Trash2 } from 'lucide-react'
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
import {
  deleteDashboard,
  duplicateOrgDashboard,
  setDashboardSchedule,
  setDefaultDashboard,
  setOrgDefaultDashboard,
  useMyDashboards,
  useOrgDashboards,
  useRevalidateAllDashboards,
} from '../api/use-dashboards-api'
import type { Dashboard, DashboardRefreshSchedule } from '../api/dashboards.types'
import { dashboardDataKey, refreshDashboard, useDashboardData } from '../api/widget-data'
import { DASHBOARD_CHOICE_KEY, parseRef, pickLanding, refKey, type DashboardRef } from '../landing'
import { DashboardFreshness } from './dashboard-freshness'
import { DashboardSwitcher } from './dashboard-switcher'
import { DashboardView } from './dashboard-view'

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

export interface DashboardHomeProps {
  /**
   * What to show when the viewer has no stored dashboard at all (and so
   * nothing to switch to). Rendered instead of the dashboard view.
   */
  empty?: ReactNode
}

export function DashboardHome({ empty }: DashboardHomeProps) {
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
        <PageHeader
          title={dashboard?.name ?? t('dashboards.title', 'Dashboard')}
          description={
            dashboard?.description ||
            t(
              'dashboards.description',
              'How exposed you are, whether it is getting better, and what to do next.'
            )
          }
        >
          <div className="flex items-center gap-2">
            <DashboardSwitcher
              personal={personal}
              organization={organization}
              active={active}
              onChoose={choose}
            />
            {dashboard && !isOrg && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCustomizing(true)}
                disabled={customizing}
              >
                <SlidersHorizontal className="me-2 h-4 w-4" aria-hidden />
                {t('dashboards.actions.customize', 'Customize')}
              </Button>
            )}
            {dashboard && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-8 w-8"
                    aria-label={t('dashboards.actions.more', 'More dashboard actions')}
                  >
                    <MoreHorizontal className="h-4 w-4" aria-hidden />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  {isOrg && (
                    <DropdownMenuItem onSelect={() => duplicate(dashboard.id)}>
                      <Copy className="me-2 h-4 w-4" aria-hidden />
                      {t('dashboards.actions.duplicate', 'Duplicate to mine')}
                    </DropdownMenuItem>
                  )}
                  {!isDefault && (!isOrg || canOrgManage) && (
                    <DropdownMenuItem
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
                  <DropdownMenuItem asChild>
                    <Link href="/dashboards">
                      <Pencil className="me-2 h-4 w-4" aria-hidden />
                      {t('dashboards.actions.edit', 'Edit details')}
                    </Link>
                  </DropdownMenuItem>
                  {!isOrg && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        className="text-destructive focus:text-destructive"
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

        {listsLoading ? (
          <DashboardSkeleton />
        ) : !dashboard || !active ? (
          (empty ?? (
            <div className="rounded-lg border border-dashed py-12 text-center text-sm text-muted-foreground">
              {t('dashboards.view.none', 'You have no dashboards yet.')}{' '}
              <Link href="/dashboards" className="font-medium text-foreground underline">
                {t('dashboards.switcher.new', 'New dashboard')}
              </Link>
            </div>
          ))
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
            <DashboardFreshness
              kind={active.kind}
              data={data.data}
              schedule={dashboard.refresh_schedule}
              canSchedule={canSchedule}
              onRefresh={refresh}
              onSchedule={schedule}
            />
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
