'use client'

import { useMemo, useState } from 'react'
import Link from '@/components/link'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  PageHeader,
  PageStack,
  EmptyState,
  DataTable,
  DataTableColumnHeader,
  ErrorState,
  CappedNotice,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Plus, RefreshCw, CalendarClock, Lightbulb } from 'lucide-react'
import { post } from '@/lib/api/client'
import { useRegisterPages } from '@/lib/api/use-register-pages'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'
import { formatDateOnly } from '@/lib/date-only'
import { toast } from 'sonner'
import { CyclePolicyCard, summarizeEvaluation, type CtemCycle } from '@/features/cycles'
import { CycleStatusBadge } from '@/features/cycles/components/cycle-status-badge'
import { useTranslation } from '@/context/i18n-provider'

// Feed-forward "lessons" callout: the muted card tone, no accent colour.
const LESSONS_CALLOUT_CLASS = 'rounded-lg border bg-muted/40 p-3'
const LESSONS_ICON_CLASS = 'h-4 w-4 text-muted-foreground'

function formatDate(dateStr: string | undefined, locale: string): string {
  return formatDateOnly(dateStr, locale) || '-'
}

// CTEM operating rhythm (https://ctem.org/docs/stages/ctem-mobilization): the
// prescribed cadence that keeps a cycle running. Purely a reference rhythm,
// no scheduler is implied; the dates are anchored to real cycle data below.
// The labels live in the catalog under scoping.cycles.cadence.<key>.
const CTEM_CADENCE = ['weekly', 'monthly', 'quarterly'] as const

// nextWeekday returns the next occurrence of the given weekday (0=Sun) from
// today, used to anchor the weekly-triage checkpoint to a real date.
function nextWeekday(weekday: number): Date {
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  const delta = (weekday - d.getDay() + 7) % 7 || 7
  d.setDate(d.getDate() + delta)
  return d
}

// firstOfNextMonth anchors the monthly-steering checkpoint.
function firstOfNextMonth(): Date {
  const d = new Date()
  return new Date(d.getFullYear(), d.getMonth() + 1, 1)
}

export default function CtemCyclesPage() {
  const { t, locale } = useTranslation()
  const router = useRouter()
  const {
    error: loadError,
    data: response,
    isLoading,
    mutate,
  } = useRegisterPages<CtemCycle>('/api/v1/ctem-cycles?per_page=100')

  const cycles = useMemo(() => response?.data ?? [], [response])

  // Feedback-to-scope loop: surface the most recent finished cycle's
  // scope-refinement notes so they visibly feed the NEXT cycle's scoping
  // (otherwise the notes are captured but never carried forward).
  const lastLessons = useMemo(() => {
    const withNotes = cycles.filter(
      (c) =>
        (c.status === 'closed' || c.status === 'review') &&
        (c.charter?.scope_refinement_notes ?? '').trim() !== ''
    )
    withNotes.sort(
      (a, b) =>
        new Date(b.end_date || b.updated_at).getTime() -
        new Date(a.end_date || a.updated_at).getTime()
    )
    return withNotes[0] ?? null
  }, [cycles])

  // The single active cycle anchors the operating-rhythm checkpoints to real
  // dates (its scope-refresh checkpoint is the cycle's own end date).
  const activeCycle = useMemo(() => cycles.find((c) => c.status === 'active') ?? null, [cycles])

  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    start_date: '',
    end_date: '',
  })
  const resetForm = () => {
    setFormData({ name: '', description: '', start_date: '', end_date: '' })
  }

  const [isCreating, setIsCreating] = useState(false)
  const handleCreate = async () => {
    if (isCreating) return
    if (!formData.name) {
      toast.error(t('scoping.cycles.nameRequired', 'Enter a cycle name.'))
      return
    }
    if (formData.start_date && formData.end_date && formData.end_date < formData.start_date) {
      toast.error(
        t('scope.cycles.endBeforeStart', 'The end date must not be before the start date.')
      )
      return
    }
    setIsCreating(true)
    try {
      const created = await post<CtemCycle>('/api/v1/ctem-cycles', formData)
      await mutate()
      toast.success(t('scoping.cycles.created', 'Cycle created.'))
      setIsCreateOpen(false)
      resetForm()
      // Straight to the new cycle, where its charter is written.
      if (created?.id) router.push(`/cycles/${created.id}`)
    } catch (err) {
      toast.error(getErrorMessage(err, t('scope.cycles.createFailed', 'Failed to create cycle')))
    } finally {
      setIsCreating(false)
    }
  }

  const columns = useMemo<ColumnDef<CtemCycle>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scoping.cycles.col.name', 'Name')} />
        ),
        cell: ({ row }) => (
          <Link href={`/cycles/${row.original.id}`} className="font-medium hover:underline">
            {row.original.name}
          </Link>
        ),
      },
      {
        accessorKey: 'status',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scoping.cycles.col.status', 'Status')} />
        ),
        cell: ({ row }) => <CycleStatusBadge status={row.original.status} />,
      },
      {
        accessorKey: 'start_date',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('scoping.cycles.col.start', 'Start date')}
          />
        ),
        cell: ({ row }) => formatDate(row.original.start_date, locale),
      },
      {
        accessorKey: 'end_date',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('scoping.cycles.col.end', 'End date')} />
        ),
        cell: ({ row }) => formatDate(row.original.end_date, locale),
      },
      {
        id: 'criteria',
        header: () => <span>{t('scoping.cycles.col.criteria', 'Success criteria')}</span>,
        enableSorting: false,
        cell: ({ row }) => {
          const ev = row.original.charter_evaluation
          const summary = summarizeEvaluation(ev, t)
          if (!summary) return <span className="text-muted-foreground">-</span>
          return (
            <Link
              href={`/cycles/${row.original.id}?tab=outcome`}
              className="text-start text-sm tabular-nums hover:underline"
              title={t('scoping.cycles.viewOutcome', 'View the success criteria outcome')}
            >
              {summary}
              {ev?.completion_rate !== undefined && (
                <span className="ms-1.5 text-xs text-muted-foreground">
                  {Math.round(ev.completion_rate)}%
                </span>
              )}
            </Link>
          )
        },
      },
    ],
    [t, locale]
  )

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={t('scope.cycles.title', 'Cycles')}
            description={t(
              'scope.cycles.description',
              'Plan and run CTEM cycles: the charter, the scope it freezes and the outcome it is judged by.'
            )}
          >
            <Can permission={Permission.CTEMCyclesWrite}>
              <Button size="sm" onClick={() => setIsCreateOpen(true)}>
                <Plus className="me-2 h-4 w-4" />
                {t('scoping.cycles.new', 'New cycle')}
              </Button>
            </Can>
          </PageHeader>

          <CyclePolicyCard />

          {/* CTEM operating rhythm: a lightweight, always-visible reminder of
            the prescribed cadence. Checkpoints are anchored to real dates: the
            weekly/monthly ones to the calendar, the quarterly scope refresh to
            the active cycle's end date. No scheduler is implied. One strip with
            dividers rather than a card of cards. */}
          <section aria-label={t('scoping.cycles.rhythm', 'Operating rhythm')}>
            <div className="grid overflow-hidden rounded-xl border bg-card sm:grid-cols-3">
              {CTEM_CADENCE.map((key) => {
                let when = ''
                if (key === 'weekly') when = formatDate(nextWeekday(1).toISOString(), locale)
                else if (key === 'monthly')
                  when = formatDate(firstOfNextMonth().toISOString(), locale)
                else if (key === 'quarterly')
                  when = activeCycle?.end_date ? formatDate(activeCycle.end_date, locale) : ''
                return (
                  <div key={key} className="-ms-px -mt-px border-s border-t px-4 py-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-2 text-sm font-medium">
                        <CalendarClock className="h-4 w-4 text-muted-foreground" />
                        {t(`scoping.cycles.cadence.${key}.label`, key)}
                      </span>
                      {when && <span className="text-xs text-muted-foreground">{when}</span>}
                    </div>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t(`scoping.cycles.cadence.${key}.detail`, key)}
                    </p>
                  </div>
                )
              })}
            </div>
            {!activeCycle && (
              <p className="mt-2 text-xs text-muted-foreground">
                {t(
                  'scoping.cycles.cadence.anchorHint',
                  'Activate a cycle to anchor the quarterly scope refresh to its end date.'
                )}
              </p>
            )}
          </section>

          <div>
            {isLoading ? (
              <div className="space-y-2 rounded-xl border p-3">
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : loadError ? (
              <ErrorState
                title={t('scope.cycles.loadError', 'cycles')}
                error={loadError}
                onRetry={() => mutate()}
              />
            ) : cycles.length === 0 ? (
              <EmptyState
                icon={RefreshCw}
                title={t('scope.cycles.emptyTitle', 'No cycles yet')}
                description={t('scope.cycles.empty', 'Create a cycle to start.')}
              />
            ) : (
              <DataTable
                columns={columns}
                data={cycles}
                onRowClick={(cycle) => router.push(`/cycles/${cycle.id}`)}
                searchPlaceholder={t('scoping.cycles.search', 'Search cycles')}
                emptyMessage={t('scoping.cycles.noMatch', 'No cycles found')}
                emptyDescription={t(
                  'scoping.cycles.noMatchHint',
                  'No cycles match the current search.'
                )}
              />
            )}
          </div>
          <CappedNotice loaded={cycles.length} total={response?.total ?? 0} />
        </PageStack>
      </Main>

      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('scoping.cycles.dialog.title', 'New CTEM cycle')}</DialogTitle>
            <DialogDescription>
              {t(
                'scoping.cycles.dialog.description',
                'Start a new continuous threat exposure management cycle.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              {/* Feed-forward: the last finished cycle's scope-refinement notes,
                shown read-only so the lessons visibly inform this new cycle's
                scope instead of being copied by hand. */}
              {lastLessons && (
                <div className={LESSONS_CALLOUT_CLASS}>
                  <div className="flex items-center gap-2 text-sm font-medium">
                    <Lightbulb className={LESSONS_ICON_CLASS} />
                    {t('scoping.cycles.lessonsFrom', 'Lessons from {name}', {
                      name: lastLessons.name,
                    })}
                  </div>
                  <p className="mt-1 whitespace-pre-wrap text-xs text-muted-foreground">
                    {lastLessons.charter?.scope_refinement_notes}
                  </p>
                  <p className="mt-1.5 text-[11px] text-muted-foreground">
                    {t(
                      'scoping.cycles.lessonsHint',
                      'Carry the relevant items into the scope and charter of this cycle.'
                    )}
                  </p>
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="name">{t('scoping.cycles.field.name', 'Name')} *</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder={t('scoping.cycles.field.namePlaceholder', 'e.g. Q2 2026 CTEM cycle')}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">
                  {t('scoping.cycles.field.description', 'Description')}
                </Label>
                <Input
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder={t(
                    'scoping.cycles.field.descriptionPlaceholder',
                    'Brief description of the cycle goals'
                  )}
                />
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="start_date">{t('scoping.cycles.col.start', 'Start date')}</Label>
                  <Input
                    id="start_date"
                    type="date"
                    value={formData.start_date}
                    onChange={(e) => setFormData({ ...formData, start_date: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="end_date">{t('scoping.cycles.col.end', 'End date')}</Label>
                  <Input
                    id="end_date"
                    type="date"
                    value={formData.end_date}
                    onChange={(e) => setFormData({ ...formData, end_date: e.target.value })}
                  />
                </div>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={isCreating}>
              {t('scoping.cycles.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
