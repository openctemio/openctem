'use client'

import { useState } from 'react'
import { Bookmark, Copy, Trash2, Users } from 'lucide-react'
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

import {
  createSavedView,
  deleteSavedView,
  duplicateSavedView,
  type SavedView,
  type SavedViewPage,
  useSavedViews,
  viewQueryFromSearch,
} from '../api/use-saved-views'

interface SavedViewsMenuProps {
  page: SavedViewPage
  /** The saved view the page shows, if any. */
  activeId?: string
  /** True when the URL has filter params on top of the active view. */
  modified?: boolean
  /** The current group-by, saved with the view. */
  groupBy?: string
  /** Open a view (the page puts `view=<id>` in its URL). */
  onSelect: (view: SavedView | null) => void
}

const PERSONAL = 'personal'

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
  groupBy,
  onSelect,
}: SavedViewsMenuProps) {
  // The list loads when it is about to be shown (pointer over or focus on the
  // button, or the menu opening), or at once when a view is active (its name
  // is the button's label) — not with every page load.
  const [wanted, setWanted] = useState(false)
  const { views, mutate } = useSavedViews(page, wanted || !!activeId)
  const [saveOpen, setSaveOpen] = useState(false)
  // Only the save dialog's "share with" picker needs the caller's groups.
  const { groups } = useMyGroups(saveOpen)
  const [name, setName] = useState('')
  const [share, setShare] = useState(PERSONAL)
  const [saving, setSaving] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<SavedView | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const { t } = useTranslation()

  const active = views.find((v) => v.id === activeId)
  const mine = views.filter((v) => v.is_owner)
  const shared = views.filter((v) => !v.is_owner)

  const save = async () => {
    setSaving(true)
    try {
      const view = await createSavedView({
        page,
        name: name.trim(),
        query: viewQueryFromSearch(window.location.search),
        group_id: share === PERSONAL ? undefined : share,
        group_by: groupBy || undefined,
      })
      await mutate()
      setSaveOpen(false)
      setName('')
      setShare(PERSONAL)
      toast.success(`Saved view "${view.name}"`)
      onSelect(view)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not save the view')
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
      toast.error(e instanceof Error ? e.message : 'Could not delete the view')
    }
  }

  const duplicate = async (view: SavedView) => {
    try {
      const copy = await duplicateSavedView(view.id)
      await mutate()
      toast.success(`Created "${copy.name}"`)
      onSelect(copy)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not duplicate the view')
    }
  }

  const item = (view: SavedView) => (
    <DropdownMenuItem
      key={view.id}
      className="flex items-center gap-2"
      onSelect={() => onSelect(view)}
    >
      <span className="flex-1 truncate">{view.name}</span>
      {view.group_name && (
        <Users
          className="h-3 w-3 text-muted-foreground"
          aria-label={`Shared with ${view.group_name}`}
        />
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
          aria-label={`Duplicate view ${view.name}`}
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
            onPointerEnter={() => setWanted(true)}
            onFocus={() => setWanted(true)}
          >
            <Bookmark className="h-4 w-4 md:me-2" />
            <span className="hidden truncate md:inline">{active ? active.name : 'Views'}</span>
            {active && modified && (
              <span className="ms-1 hidden text-xs text-muted-foreground md:inline">
                (modified)
              </span>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          {mine.length > 0 && <DropdownMenuLabel>My views</DropdownMenuLabel>}
          {mine.map(item)}
          {shared.length > 0 && <DropdownMenuLabel>Shared with my groups</DropdownMenuLabel>}
          {shared.map(item)}
          {views.length > 0 && <DropdownMenuSeparator />}
          {active && (
            <DropdownMenuItem onSelect={() => onSelect(null)}>Clear view</DropdownMenuItem>
          )}
          <DropdownMenuItem onSelect={() => setSaveOpen(true)}>
            Save current filters as a view
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={saveOpen} onOpenChange={setSaveOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Save view</DialogTitle>
            <DialogDescription>
              Saves the current filters, sort and grouping. A shared view shares the filters, not
              the results: everyone sees the findings they are allowed to see.
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="saved-view-name">Name</Label>
                <Input
                  id="saved-view-name"
                  value={name}
                  maxLength={120}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="saved-view-share">Visible to</Label>
                <Select value={share} onValueChange={setShare}>
                  <SelectTrigger id="saved-view-share">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={PERSONAL}>Only me</SelectItem>
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
              Cancel
            </Button>
            <Button onClick={() => void save()} disabled={saving || name.trim() === ''}>
              Save
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
