'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { useRouter, useSearchParams } from 'next/navigation'
import {
  ArrowLeft,
  ExternalLink,
  LayoutDashboard,
  MoreHorizontal,
  Pencil,
  Plus,
  Star,
  Trash2,
} from 'lucide-react'
import Link from '@/components/link'
import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  ErrorState,
  PageHeader,
  PageStack,
  RelativeTime,
  StackedCell,
} from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { ActionMenu } from '@/components/ui/action-menu'
import { uniqueDashboardName } from '@/features/dashboards/lib/unique-name'
import { Skeleton } from '@/components/ui/skeleton'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  DASHBOARD_TEMPLATES,
  templateDescriptionKey,
  templateLayout,
  templateNameKey,
} from '@/features/dashboards/templates'
import { DASHBOARD_CHOICE_KEY, refKey } from '@/features/dashboards/landing'
import {
  useMyDashboards,
  useMyDashboard,
  useRevalidateDashboards,
  createDashboard,
  updateDashboard,
  deleteDashboard,
  setDefaultDashboard,
  updateOrgDashboard,
  useOrgDashboard,
  useRevalidateAllDashboards,
} from '@/features/dashboards/api/use-dashboards-api'
import type {
  Dashboard,
  DashboardKind,
  DashboardWidget,
} from '@/features/dashboards/api/dashboards.types'

/**
 * Dashboards manage surface (RFC-021). A dashboard here is a *container* — its
 * name, description and column layout. Editing the actual widgets (add / remove /
 * drag / resize) happens on the live dashboard view, not on this page. Users pick
 * a template or a blank, then shape each dashboard's identity + layout here and
 * open it to populate it.
 */
export default function DashboardsPage() {
  // The edit form is part of the URL (`?edit=<id>`): Back returns to the list
  // and the form can be linked to.
  const router = useRouter()
  const params = useSearchParams()
  const editId = params?.get('edit') || null
  // `&kind=organization` edits an organization dashboard (the server checks
  // dashboards:org:manage); it is opened from the dashboard itself, so Back
  // returns there.
  const kind: DashboardKind = params?.get('kind') === 'organization' ? 'organization' : 'personal'

  if (editId) {
    return (
      <DashboardEditForm
        id={editId}
        kind={kind}
        onBack={() => router.push(kind === 'organization' ? '/' : '/dashboards')}
      />
    )
  }
  return (
    <DashboardsList onEdit={(id) => router.push(`/dashboards?edit=${encodeURIComponent(id)}`)} />
  )
}

// ── Column-layout picker options ─────────────────────────────────────────────

const LAYOUT_OPTIONS = [1, 2, 3, 4]

function rememberChoice(id: string, kind: DashboardKind = 'personal') {
  try {
    window.localStorage.setItem(DASHBOARD_CHOICE_KEY, refKey({ kind, id }))
  } catch {
    // A per-viewer convenience only.
  }
}

function LayoutPreview({ cols, active }: { cols: number; active: boolean }) {
  return (
    <div
      className={cn(
        'flex h-16 w-24 items-stretch gap-1 rounded-md border-2 p-1.5 transition-colors',
        active ? 'border-primary bg-primary/5' : 'border-border bg-muted/40 hover:border-primary/40'
      )}
    >
      {Array.from({ length: cols }).map((_, i) => (
        <div
          key={i}
          className={cn('flex-1 rounded-sm', active ? 'bg-primary/70' : 'bg-muted-foreground/30')}
        />
      ))}
    </div>
  )
}

// ── List + template gallery ──────────────────────────────────────────────────

/**
 * Your dashboards as one table (name with the default star, widgets,
 * columns, last change, a row menu), then the templates to start from. A
 * row opens the dashboard; the menu customizes it, edits its details, makes
 * it the default or deletes it (confirmed).
 */
function DashboardsList({ onEdit }: { onEdit: (id: string) => void }) {
  const router = useRouter()
  const { data, isLoading, error, mutate } = useMyDashboards()
  const revalidate = useRevalidateDashboards()
  const [busy, setBusy] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<{ id: string; name: string } | null>(null)
  const { t } = useTranslation()
  const saved = useMemo(() => data?.data ?? [], [data])

  const openView = useCallback(
    (id: string, customize = false) => {
      rememberChoice(id)
      router.push(customize ? '/?customize=1' : '/')
    },
    [router]
  )
  // A template copy opens on the dashboard itself (it is ready to read); a
  // blank one opens its details form, as there is nothing to see yet.
  const createFrom = async (
    name: string,
    layout: DashboardWidget[],
    columns = 2,
    description = ''
  ) => {
    setBusy(true)
    try {
      const d = await createDashboard({
        name: uniqueDashboardName(
          name,
          saved.map((x) => x.name),
          name
        ),
        description,
        layout,
        columns,
      })
      await revalidate()
      if (layout.length > 0) openView(d.id)
      else onEdit(d.id)
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id: string, name: string) => {
    try {
      await deleteDashboard(id)
      await revalidate()
      setPendingDelete(null)
      toast.success(t('confirm.dashboard.deleted', 'Dashboard "{name}" deleted', { name }))
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

  const makeDefault = useCallback(
    async (id: string) => {
      try {
        await setDefaultDashboard(id)
        await revalidate()
      } catch (e) {
        toast.error(getErrorMessage(e))
      }
    },
    [revalidate]
  )

  const columns = useMemo<ColumnDef<Dashboard>[]>(
    () => [
      {
        id: 'name',
        meta: { kind: 'name', label: t('dashboards.manage.name', 'Name') },
        header: t('dashboards.manage.name', 'Name'),
        cell: ({ row }) => (
          <StackedCell
            truncate
            primary={
              <span className="inline-flex min-w-0 items-center gap-1.5">
                {/* The name opens the dashboard (a link, so it is reachable
                    by keyboard); a click anywhere else on the row does too. */}
                <Link
                  href="/"
                  className="truncate font-medium hover:underline"
                  onClick={() => rememberChoice(row.original.id)}
                  // Stored text, in the language it was written in: not catalog copy.
                  translate="no"
                >
                  {row.original.name}
                </Link>
                {row.original.is_default && (
                  <Star
                    className="h-3.5 w-3.5 shrink-0 fill-current text-muted-foreground"
                    role="img"
                    aria-label={t('dashboards.switcher.default', 'Default')}
                  />
                )}
              </span>
            }
            secondary={
              row.original.description ? (
                // Stored text, in the language it was written in: not catalog copy.
                <span translate="no">{row.original.description}</span>
              ) : undefined
            }
          />
        ),
      },
      {
        id: 'widgets',
        meta: { kind: 'number', label: t('dashboards.manage.widgetsCol', 'Widgets') },
        header: t('dashboards.manage.widgetsCol', 'Widgets'),
        cell: ({ row }) => row.original.layout.length,
      },
      {
        id: 'columns',
        meta: { kind: 'text', label: t('dashboards.manage.layout', 'Layout') },
        header: t('dashboards.manage.layout', 'Layout'),
        cell: ({ row }) =>
          t('dashboards.manage.columns', '{n} columns', { n: row.original.columns ?? 2 }),
      },
      {
        id: 'updated',
        meta: { kind: 'datetime-recent', label: t('dashboards.manage.updated', 'Updated') },
        header: t('dashboards.manage.updated', 'Updated'),
        cell: ({ row }) =>
          row.original.updated_at ? <RelativeTime date={row.original.updated_at} /> : null,
      },
      {
        id: 'actions',
        meta: { kind: 'actions', label: t('components.col.actions', 'Actions') },
        enableSorting: false,
        enableHiding: false,
        header: () => <span className="sr-only">{t('components.col.actions', 'Actions')}</span>,
        cell: ({ row }) => {
          const d = row.original
          const label = t('common.actionMenu.label', 'Actions for {name}', { name: d.name })
          return (
            <ActionMenu
              title={d.name}
              label={label}
              items={[
                {
                  id: 'customize',
                  label: t('dashboards.manage.customize', 'Customize'),
                  icon: LayoutDashboard,
                  onSelect: () => openView(d.id, true),
                },
                {
                  id: 'edit',
                  label: t('dashboards.actions.edit', 'Edit details'),
                  icon: Pencil,
                  onSelect: () => onEdit(d.id),
                },
                ...(!d.is_default
                  ? [
                      {
                        id: 'set-default',
                        label: t('dashboards.actions.setDefault', 'Set as my default'),
                        icon: Star,
                        onSelect: () => void makeDefault(d.id),
                      },
                    ]
                  : []),
                {
                  id: 'delete',
                  label: t('dashboards.actions.delete', 'Delete'),
                  icon: Trash2,
                  destructive: true,
                  onSelect: () => setPendingDelete({ id: d.id, name: d.name }),
                },
              ]}
              trigger={
                <Button type="button" size="icon-sm" variant="ghost" aria-label={label}>
                  <MoreHorizontal className="h-4 w-4" aria-hidden />
                </Button>
              }
            />
          )
        },
      },
    ],
    [t, openView, onEdit, makeDefault]
  )

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('dashboards.manage.title', 'Dashboards')}
          description={t(
            'dashboards.manage.description',
            'Start from a template or build your own. Your dashboards are computed for your own access.'
          )}
        >
          <Button
            disabled={busy}
            onClick={() => createFrom(t('dashboards.manage.blankName', 'My dashboard'), [])}
          >
            <Plus aria-hidden />
            {t('dashboards.switcher.new', 'New dashboard')}
          </Button>
        </PageHeader>

        <section className="flex flex-col gap-2" aria-labelledby="dashboards-yours">
          <h2 id="dashboards-yours" className="text-section">
            {t('dashboards.manage.yours', 'Your dashboards')}
          </h2>
          {error && !data ? (
            <ErrorState
              title={t('dashboards.manage.yoursWhat', 'your dashboards')}
              error={error}
              onRetry={() => void mutate()}
            />
          ) : (
            <DataTable
              columns={columns}
              data={saved}
              getRowId={(d) => d.id}
              isLoading={isLoading}
              caption={t('dashboards.manage.yours', 'Your dashboards')}
              // A short list of one's own dashboards: nothing to search, so no
              // toolbar row (a lone Display button wasted it).
              showToolbar={false}
              showSearch={false}
              showColumnToggle={false}
              showSelectionCount={false}
              showPagination={false}
              mobileCards
              onRowClick={(d) => openView(d.id)}
              emptyMessage={t(
                'dashboards.manage.none',
                'No dashboards yet. Copy a template below to get started.'
              )}
            />
          )}
          {saved.some((d) => d.is_default) && (
            <p className="text-xs text-muted-foreground">
              {t(
                'dashboards.manage.starNote',
                'The star marks your default: the dashboard you see first.'
              )}
            </p>
          )}
        </section>

        {/* The templates follow the list once it has its rows: while the
            list loads it shows skeleton rows of a guessed count, and content
            below it would jump when the real rows replace them. */}
        {!isLoading && (
          <section className="flex flex-col gap-2" aria-labelledby="dashboards-templates">
            <h2 id="dashboards-templates" className="text-section">
              {t('dashboards.manage.templates', 'Start from a template')}
            </h2>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {DASHBOARD_TEMPLATES.map((tpl) => (
                <Card key={tpl.key} className="flex flex-col">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">
                      {t(templateNameKey(tpl.key), tpl.key)}
                    </CardTitle>
                    <CardDescription>{t(templateDescriptionKey(tpl.key), '')}</CardDescription>
                  </CardHeader>
                  <CardContent className="mt-auto flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">
                      {t('dashboards.manage.widgetCount', '{n} widgets', { n: tpl.widgets.length })}
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() =>
                        createFrom(
                          t(templateNameKey(tpl.key), tpl.key),
                          templateLayout(tpl),
                          tpl.columns,
                          t(templateDescriptionKey(tpl.key), '')
                        )
                      }
                    >
                      {t('dashboards.manage.useTemplate', 'Use template')}
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </section>
        )}
        <ConfirmDialog
          open={pendingDelete !== null}
          onOpenChange={(open) => !open && setPendingDelete(null)}
          destructive
          title={t('confirm.dashboard.deleteTitle', 'Delete dashboard "{name}"?', {
            name: pendingDelete?.name ?? '',
          })}
          desc={t(
            'confirm.dashboard.deleteDescPersonal',
            'Your dashboard and its layout are deleted. Copies you shared and the data behind the widgets are not affected.'
          )}
          confirmText={t('confirm.dashboard.deleteButton', 'Delete dashboard')}
          handleConfirm={() =>
            pendingDelete ? remove(pendingDelete.id, pendingDelete.name) : undefined
          }
        />
      </PageStack>
    </Main>
  )
}

// ── Edit form: name + description + layout only ──────────────────────────────

function DashboardEditForm({
  id,
  kind,
  onBack,
}: {
  id: string
  kind: DashboardKind
  onBack: () => void
}) {
  const router = useRouter()
  const isOrg = kind === 'organization'
  const mine = useMyDashboard(isOrg ? null : id)
  const org = useOrgDashboard(isOrg ? id : null)
  const { data, isLoading } = isOrg ? org : mine
  const revalidate = useRevalidateAllDashboards()
  const { t } = useTranslation()

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [columns, setColumns] = useState(2)
  const [ready, setReady] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (ready || isLoading || !data) return
    setName(data.name)
    setDescription(data.description ?? '')
    setColumns(data.columns ?? 2)
    setReady(true)
  }, [ready, isLoading, data])

  const submit = async (thenOpen: boolean) => {
    if (!data) return
    const trimmed = name.trim()
    if (!trimmed) {
      toast.error(t('dashboards.manage.nameRequired', 'Name is required'))
      return
    }
    setSaving(true)
    try {
      // Widths are stored on a 12-unit grid and map to any column count, so
      // a new column count keeps every widget's share of the row.
      const layout: DashboardWidget[] = data.layout
      const input = { name: trimmed, description: description.trim(), columns, layout }
      await (isOrg ? updateOrgDashboard(id, input) : updateDashboard(id, input))
      await revalidate()
      if (thenOpen) {
        rememberChoice(id, kind)
        router.push('/')
      } else {
        onBack()
      }
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  if (isLoading || !ready) {
    return (
      <Main>
        <PageStack>
          <Skeleton className="h-9 w-48" />
          <div className="mx-auto w-full max-w-3xl space-y-4">
            <Skeleton className="h-40 w-full" />
            <Skeleton className="h-32 w-full" />
          </div>
        </PageStack>
      </Main>
    )
  }

  if (!data) {
    return (
      <Main>
        <PageStack>
          <Button variant="ghost" onClick={onBack} className="self-start">
            <ArrowLeft className="me-2 h-4 w-4" aria-hidden /> {t('dashboards.manage.back', 'Back')}
          </Button>
          <div className="rounded-lg border border-dashed py-10 text-center text-sm text-muted-foreground">
            {t('dashboards.manage.notFound', 'Dashboard not found.')}
          </div>
        </PageStack>
      </Main>
    )
  }

  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('dashboards.manage.editTitle', 'Edit dashboard')}
          description={t(
            'dashboards.manage.editDescription',
            'Set the name, description and number of columns. Add and arrange widgets on the dashboard itself.'
          )}
        >
          <div className="flex gap-2">
            <Button variant="ghost" onClick={onBack}>
              <ArrowLeft className="me-2 h-4 w-4" aria-hidden />{' '}
              {t('dashboards.manage.back', 'Back')}
            </Button>
            <Button variant="outline" disabled={saving} onClick={() => submit(true)}>
              <ExternalLink className="me-2 h-4 w-4" aria-hidden />{' '}
              {t('dashboards.manage.saveOpen', 'Save and open')}
            </Button>
            <Button disabled={saving} onClick={() => submit(false)}>
              {saving
                ? t('dashboards.manage.saving', 'Saving')
                : t('dashboards.editor.save', 'Save')}
            </Button>
          </div>
        </PageHeader>

        <div className="mx-auto w-full max-w-3xl space-y-6">
          {/* General */}
          <section className="space-y-4">
            <h2 className="text-base font-medium">{t('dashboards.manage.general', 'General')}</h2>
            <div className="space-y-1.5">
              <label htmlFor="dash-name" className="text-sm font-medium">
                {t('dashboards.manage.name', 'Name')} <span className="text-destructive">*</span>
              </label>
              <Input
                id="dash-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={100}
                placeholder={t(
                  'dashboards.manage.namePlaceholder',
                  'For example: Executive overview'
                )}
              />
            </div>
            <div className="space-y-1.5">
              <label htmlFor="dash-desc" className="text-sm font-medium">
                {t('dashboards.manage.descriptionLabel', 'Description')}
              </label>
              <Textarea
                id="dash-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={500}
                rows={3}
                placeholder={t(
                  'dashboards.manage.descriptionPlaceholder',
                  'What is this dashboard for? (optional)'
                )}
              />
              <p className="text-xs text-muted-foreground">{description.length}/500</p>
            </div>
          </section>

          {/* Layout */}
          <section className="space-y-3 border-t pt-6">
            <div>
              <h2 className="text-base font-medium">{t('dashboards.manage.layout', 'Layout')}</h2>
              <p className="text-sm text-muted-foreground">
                {t(
                  'dashboards.manage.layoutHint',
                  'How many columns the dashboard is arranged in. Each widget keeps its share of the row.'
                )}
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              {LAYOUT_OPTIONS.map((cols) => (
                <button
                  key={cols}
                  type="button"
                  onClick={() => setColumns(cols)}
                  className="flex flex-col items-center gap-1.5"
                  aria-pressed={columns === cols}
                  aria-label={t('dashboards.manage.columns', '{n} columns', { n: cols })}
                >
                  <LayoutPreview cols={cols} active={columns === cols} />
                  <span
                    className={cn(
                      'text-xs',
                      columns === cols ? 'font-medium text-foreground' : 'text-muted-foreground'
                    )}
                  >
                    {cols}
                  </span>
                </button>
              ))}
            </div>
          </section>
        </div>
      </PageStack>
    </Main>
  )
}
