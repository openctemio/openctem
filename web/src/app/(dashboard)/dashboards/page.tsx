'use client'

import { useEffect, useState } from 'react'
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
import { Main } from '@/components/layout'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { PageHeader, PageStack } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
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
import type { DashboardKind, DashboardWidget } from '@/features/dashboards/api/dashboards.types'

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

/** Menu rows are 44px tall on a phone (touch target), the kit default from 640px. */
const ITEM = 'min-h-11 sm:min-h-8'

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

function DashboardsList({ onEdit }: { onEdit: (id: string) => void }) {
  const router = useRouter()
  const { data, isLoading } = useMyDashboards()
  const revalidate = useRevalidateDashboards()
  const [busy, setBusy] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<{ id: string; name: string } | null>(null)
  const { t } = useTranslation()
  const saved = data?.data ?? []

  const openView = (id: string, customize = false) => {
    rememberChoice(id)
    router.push(customize ? '/?customize=1' : '/')
  }
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

  const makeDefault = async (id: string) => {
    try {
      await setDefaultDashboard(id)
      await revalidate()
    } catch (e) {
      toast.error(getErrorMessage(e))
    }
  }

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
            variant="outline"
            disabled={busy}
            onClick={() => createFrom(t('dashboards.manage.blankName', 'My dashboard'), [])}
          >
            <Plus className="me-2 h-4 w-4" aria-hidden />{' '}
            {t('dashboards.manage.newBlank', 'New blank')}
          </Button>
        </PageHeader>

        {/* Templates */}
        <section>
          <h2 className="mb-3 text-sm font-medium text-muted-foreground">
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

        {/* Saved */}
        <section>
          <h2 className="mb-3 text-sm font-medium text-muted-foreground">
            {t('dashboards.manage.yours', 'Your dashboards')}
          </h2>
          {isLoading ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-28 w-full" />
              ))}
            </div>
          ) : saved.length === 0 ? (
            <div className="rounded-lg border border-dashed py-10 text-center text-sm text-muted-foreground">
              {t(
                'dashboards.manage.none',
                'No dashboards yet. Copy a template above to get started.'
              )}
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {saved.map((d) => (
                <Card key={d.id} className="flex flex-col">
                  <CardHeader className="pb-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <button
                        type="button"
                        className="min-w-0 truncate text-start hover:underline"
                        onClick={() => openView(d.id)}
                      >
                        {d.name}
                      </button>
                      {d.is_default && (
                        <Badge variant="secondary" className="shrink-0 gap-1">
                          <Star className="h-3 w-3" aria-hidden />{' '}
                          {t('dashboards.switcher.default', 'Default')}
                        </Badge>
                      )}
                    </CardTitle>
                    {d.description ? (
                      <CardDescription className="line-clamp-2">{d.description}</CardDescription>
                    ) : null}
                  </CardHeader>
                  <CardContent className="mt-auto flex flex-wrap items-center justify-between gap-2">
                    <span className="flex gap-3 whitespace-nowrap text-xs text-muted-foreground">
                      <span>
                        {t('dashboards.manage.widgets', '{n} widgets', { n: d.layout.length })}
                      </span>
                      <span>
                        {t('dashboards.manage.columns', '{n} columns', { n: d.columns ?? 2 })}
                      </span>
                    </span>
                    <div className="flex items-center gap-1">
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => openView(d.id)}
                      >
                        <ExternalLink className="me-2 h-4 w-4" aria-hidden />
                        {t('dashboards.manage.open', 'Open')}
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => openView(d.id, true)}
                      >
                        <LayoutDashboard className="me-2 h-4 w-4" aria-hidden />
                        {t('dashboards.manage.customize', 'Customize')}
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            type="button"
                            size="icon"
                            variant="ghost"
                            className="h-8 w-8"
                            aria-label={t('dashboards.manage.moreFor', 'More actions for {name}', {
                              name: d.name,
                            })}
                          >
                            <MoreHorizontal className="h-4 w-4" aria-hidden />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-56">
                          <DropdownMenuItem className={ITEM} onSelect={() => onEdit(d.id)}>
                            <Pencil className="me-2 h-4 w-4" aria-hidden />
                            {t('dashboards.actions.edit', 'Edit details')}
                          </DropdownMenuItem>
                          {!d.is_default && (
                            <DropdownMenuItem className={ITEM} onSelect={() => makeDefault(d.id)}>
                              <Star className="me-2 h-4 w-4" aria-hidden />
                              {t('dashboards.actions.setDefault', 'Set as my default')}
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className={cn(ITEM, 'text-destructive focus:text-destructive')}
                            onSelect={() => setPendingDelete({ id: d.id, name: d.name })}
                          >
                            <Trash2 className="me-2 h-4 w-4" aria-hidden />
                            {t('dashboards.actions.delete', 'Delete')}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </section>
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
