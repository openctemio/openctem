'use client'

import { useState } from 'react'
import { Bookmark, Building2, Copy, Pin, PinOff, Trash2, Users } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useMyGroups } from '@/features/access-control/api/use-groups'
import { useNavPins } from '@/features/nav-pins/api/use-nav-pins'
import { Permission, usePermissions } from '@/lib/permissions'
import type { ViewChange } from '../lib/view-changes'

import {
  createSavedView,
  deleteSavedView,
  duplicateSavedView,
  updateSavedView,
  type SavedView,
  type SavedViewPage,
  useSavedViews,
  viewQueryFromSearch,
} from '../api/use-saved-views'

interface SavedViewsMenuProps {
  page: SavedViewPage
  /** The saved view the page shows, if any. */
  activeId?: string
  /** True when the list differs from the active view (used when `changes` is not given). */
  modified?: boolean
  /** What differs from the active view; any change shows the unsaved-changes dot. */
  changes?: ViewChange[]
  /** The current group-by, saved with the view. */
  groupBy?: string
  /** The optional columns the list shows, saved with the view. */
  columns?: string[]
  /** The row density the list shows, saved with the view (omitted when no choice was made). */
  density?: string
  /** Throw away the unsaved changes: back to the view as saved. */
  onDiscard?: () => void
  /** Open a view (the page puts `view=<id>` in its URL). */
  onSelect: (view: SavedView | null) => void
}

const PERSONAL = 'personal'
/** The share option for the whole organization (findings:views:share). */
const ORGANIZATION = 'organization'

/** "2 filters added, columns changed": what the unsaved dot stands for. */
export function summarizeChanges(
  changes: ViewChange[],
  t: (key: string, fallback?: string, vars?: Record<string, string | number>) => string
): string {
  return changes
    .map((c) => {
      switch (c.kind) {
        case 'filters':
          return t(
            'confirm.savedView.change.filters',
            '{count, plural, one {# filter added} other {# filters added}}',
            { count: c.count }
          )
        case 'search':
          return t('confirm.savedView.change.search', 'search changed')
        case 'sort':
          return t('confirm.savedView.change.sort', 'sort changed')
        case 'group':
          return t('confirm.savedView.change.group', 'grouping changed')
        case 'columns':
          return t('confirm.savedView.change.columns', 'columns changed')
        case 'density':
          return t('confirm.savedView.change.density', 'density changed')
      }
    })
    .join(', ')
}

/**
 * The toolbar's saved views menu (UI contract D15): open a view, save the
 * current filter as a view (personal or shared with one of your groups),
 * delete your own, duplicate a shared one. Sharing a view shares the query,
 * not the rows: each person sees their own scoped results.
 */
export function SavedViewsMenu({
  page,
  activeId,
  modified,
  changes,
  groupBy,
  columns,
  density,
  onDiscard,
  onSelect,
}: SavedViewsMenuProps) {
  // The list loads when it is about to be shown (pointer over or focus on the
  // button, or the menu opening), or at once when a view is active (its name
  // is the button's label) — not with every page load.
  const [wanted, setWanted] = useState(false)
  const { views, mutate } = useSavedViews(page, wanted || !!activeId)
  // Findings views can be pinned to the top of the sidebar.
  const navPins = useNavPins()
  const pinnable = page === 'findings'
  const [saveOpen, setSaveOpen] = useState(false)
  // Only the save dialog's "share with" picker needs the caller's groups.
  const { groups } = useMyGroups(saveOpen)
  const [name, setName] = useState('')
  const [share, setShare] = useState(PERSONAL)
  const { can } = usePermissions()
  const canShareOrg = can(Permission.FindingsViewsShare)
  const [saving, setSaving] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<SavedView | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const { t } = useTranslation()

  const active = views.find((v) => v.id === activeId)
  const mine = views.filter((v) => v.is_owner)
  const shared = views.filter((v) => !v.is_owner)
  const dirty = !!active && (changes ? changes.length > 0 : !!modified)

  const save = async () => {
    setSaving(true)
    try {
      const view = await createSavedView({
        page,
        name: name.trim(),
        query: viewQueryFromSearch(window.location.search),
        group_id: share === PERSONAL || share === ORGANIZATION ? undefined : share,
        ...(share === ORGANIZATION ? { share_with_org: true } : {}),
        group_by: groupBy || undefined,
        columns,
        density,
      })
      await mutate()
      setSaveOpen(false)
      setName('')
      setShare(PERSONAL)
      toast.success(t('confirm.savedView.saved', 'Saved view "{name}"', { name: view.name }))
      onSelect(view)
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('confirm.savedView.saveFailed', 'Could not save the view')
      )
    } finally {
      setSaving(false)
    }
  }

  /** Saves the changes into the open view (its owner only). */
  const saveChanges = async () => {
    if (!active) return
    setSaving(true)
    try {
      const view = await updateSavedView(active.id, {
        page,
        name: active.name,
        description: active.description,
        // The open view stays in the query: the API saves its filter with the
        // URL's filters on top, as the list runs it.
        query: viewQueryFromSearch(window.location.search),
        group_id: active.group_id,
        ...(active.shared_with_org ? { share_with_org: true } : {}),
        group_by: groupBy || undefined,
        columns,
        density,
      })
      await mutate()
      toast.success(t('confirm.savedView.updated', 'Updated view "{name}"', { name: view.name }))
      onDiscard?.()
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('confirm.savedView.saveFailed', 'Could not save the view')
      )
    } finally {
      setSaving(false)
    }
  }

  const remove = async (view: SavedView) => {
    try {
      await deleteSavedView(view.id)
      await mutate()
      if (view.id === activeId) onSelect(null)
      setPendingDelete(null)
      toast.success(t('confirm.savedView.deleted', 'View "{name}" deleted', { name: view.name }))
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('confirm.savedView.deleteFailed', 'Could not delete the view')
      )
    }
  }

  const duplicate = async (view: SavedView) => {
    try {
      const copy = await duplicateSavedView(view.id)
      await mutate()
      toast.success(t('confirm.savedView.created', 'Created "{name}"', { name: copy.name }))
      onSelect(copy)
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('confirm.savedView.duplicateFailed', 'Could not duplicate the view')
      )
    }
  }

  const item = (view: SavedView) => (
    <DropdownMenuItem
      key={view.id}
      className="flex items-center gap-2"
      onSelect={() => onSelect(view)}
    >
      <span className="flex-1 truncate">{view.name}</span>
      {view.shared_with_org && (
        <Building2
          className="h-3 w-3 text-muted-foreground"
          aria-label={t('confirm.savedView.sharedWithOrg', 'Shared with the organization')}
        />
      )}
      {view.group_name && (
        <Users
          className="h-3 w-3 text-muted-foreground"
          aria-label={t('confirm.savedView.sharedWith', 'Shared with {group}', {
            group: view.group_name,
          })}
        />
      )}
      {pinnable && (
        <button
          type="button"
          className="rounded-sm p-0.5 hover:bg-muted"
          aria-pressed={navPins.isPinned({ kind: 'saved_view', ref: view.id })}
          aria-label={
            navPins.isPinned({ kind: 'saved_view', ref: view.id })
              ? t('nav.pins.unpin', 'Unpin {name}', { name: view.name })
              : t('nav.pins.pin', 'Pin {name} to the top', { name: view.name })
          }
          onClick={(e) => {
            e.stopPropagation()
            e.preventDefault()
            void navPins.toggle({ kind: 'saved_view', ref: view.id })
          }}
        >
          {navPins.isPinned({ kind: 'saved_view', ref: view.id }) ? (
            <PinOff className="h-3 w-3" aria-hidden />
          ) : (
            <Pin className="h-3 w-3" aria-hidden />
          )}
        </button>
      )}
      {view.is_owner ? (
        <button
          type="button"
          className="rounded-sm p-0.5 hover:bg-muted"
          aria-label={t('confirm.savedView.deleteLabel', 'Delete view {name}', { name: view.name })}
          onClick={(e) => {
            // Close the menu and ask first; the row's own click opens the view.
            e.stopPropagation()
            e.preventDefault()
            setMenuOpen(false)
            setPendingDelete(view)
          }}
        >
          <Trash2 className="h-3 w-3" />
        </button>
      ) : (
        <button
          type="button"
          className="rounded-sm p-0.5 hover:bg-muted"
          aria-label={t('confirm.savedView.duplicateLabel', 'Duplicate view {name}', {
            name: view.name,
          })}
          onClick={(e) => {
            e.stopPropagation()
            void duplicate(view)
          }}
        >
          <Copy className="h-3 w-3" />
        </button>
      )}
    </DropdownMenuItem>
  )

  return (
    <>
      <DropdownMenu
        open={menuOpen}
        onOpenChange={(open) => {
          setMenuOpen(open)
          if (open) setWanted(true)
        }}
      >
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            className="h-9 max-w-[14rem]"
            // The name stays readable when only the icon shows (narrow toolbar).
            aria-label={
              active
                ? dirty
                  ? t('confirm.savedView.triggerDirty', '{name}, unsaved changes', {
                      name: active.name,
                    })
                  : active.name
                : t('confirm.savedView.trigger', 'Views')
            }
            data-dirty={dirty ? 'true' : undefined}
            onPointerEnter={() => setWanted(true)}
            onFocus={() => setWanted(true)}
          >
            {/* Label by the list toolbar's width (DataTable's size container). */}
            <Bookmark className="h-4 w-4 @2xl/toolbar:me-2" />
            <span className="hidden truncate @2xl/toolbar:inline">
              {active ? active.name : t('confirm.savedView.trigger', 'Views')}
            </span>
            {dirty && (
              // The unsaved-changes dot: state by shape and colour, never colour alone
              // (the button's name says it too).
              <span
                data-testid="saved-view-dirty-dot"
                aria-hidden
                className="ms-1.5 size-2 shrink-0 rounded-full bg-warning"
              />
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          {dirty && active && (
            <>
              <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                {t('confirm.savedView.unsaved', 'Unsaved changes to “{name}”: {changes}', {
                  name: active.name,
                  changes: changes ? summarizeChanges(changes, t) : '',
                })}
              </DropdownMenuLabel>
              {active.is_owner && (
                <DropdownMenuItem disabled={saving} onSelect={() => void saveChanges()}>
                  {t('confirm.savedView.saveChanges', 'Save changes')}
                </DropdownMenuItem>
              )}
              <DropdownMenuItem onSelect={() => setSaveOpen(true)}>
                {t('confirm.savedView.saveAsNew', 'Save as new view…')}
              </DropdownMenuItem>
              {onDiscard && (
                <DropdownMenuItem onSelect={onDiscard}>
                  {t('confirm.savedView.discard', 'Discard changes')}
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
            </>
          )}
          {mine.length > 0 && (
            <DropdownMenuLabel>{t('confirm.savedView.mine', 'My views')}</DropdownMenuLabel>
          )}
          {mine.map(item)}
          {shared.length > 0 && (
            <DropdownMenuLabel>
              {t('confirm.savedView.sharedWithMyGroups', 'Shared with my groups')}
            </DropdownMenuLabel>
          )}
          {shared.map(item)}
          {views.length > 0 && <DropdownMenuSeparator />}
          {active && (
            <DropdownMenuItem onSelect={() => onSelect(null)}>
              {t('confirm.savedView.clear', 'Clear view')}
            </DropdownMenuItem>
          )}
          <DropdownMenuItem onSelect={() => setSaveOpen(true)}>
            {t('confirm.savedView.saveCurrent', 'Save current filters as a view')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('confirm.savedView.saveTitle', 'Save view')}</DialogTitle>
            <DialogDescription>
              {t(
                'confirm.savedView.saveDesc',
                'Saves the current filters, sort and grouping. A shared view shares the filters, not the results: everyone sees the findings they are allowed to see.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="saved-view-name">{t('confirm.savedView.name', 'Name')}</Label>
                <Input
                  id="saved-view-name"
                  value={name}
                  maxLength={120}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="saved-view-share">
                  {t('confirm.savedView.visibleTo', 'Visible to')}
                </Label>
                <Select value={share} onValueChange={setShare}>
                  <SelectTrigger id="saved-view-share">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={PERSONAL}>
                      {t('confirm.savedView.onlyMe', 'Only me')}
                    </SelectItem>
                    {canShareOrg && (
                      <SelectItem value={ORGANIZATION}>
                        {t('confirm.savedView.everyone', 'Everyone in the organization')}
                      </SelectItem>
                    )}
                    {groups.map((g) => (
                      <SelectItem key={g.id} value={g.id}>
                        {g.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSaveOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={() => void save()} disabled={saving || name.trim() === ''}>
              {t('common.save', 'Save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        destructive
        title={t('confirm.savedView.deleteTitle', 'Delete view "{name}"?', {
          name: pendingDelete?.name ?? '',
        })}
        desc={
          pendingDelete?.group_name
            ? t(
                'confirm.savedView.deleteSharedDesc',
                'The view is also removed for everyone in {group}. The data it shows is not affected. This cannot be undone.',
                { group: pendingDelete.group_name }
              )
            : t(
                'confirm.savedView.deleteDesc',
                'The saved filters are deleted. The data they show is not affected. This cannot be undone.'
              )
        }
        confirmText={t('confirm.delete', 'Delete')}
        handleConfirm={() => (pendingDelete ? remove(pendingDelete) : undefined)}
      />
    </>
  )
}
