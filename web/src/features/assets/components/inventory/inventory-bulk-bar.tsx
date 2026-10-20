'use client'

/**
 * Bulk actions for the All-Assets inventory, in the shared floating
 * BulkActionBar (it overlays the page, so selecting rows never moves the
 * table; Escape clears the selection). An operator can apply an action to the
 * whole selection: assign an owner, set criticality, add a tag, or add the
 * assets to a business unit or service. Every mutation is tenant-scoped (it goes
 * through the shared API client) and gated on `assets:write` by the caller.
 *
 * Writes run in small concurrent batches (mirrors bulkDeleteAssets) with
 * Promise.allSettled so a partial failure is surfaced rather than swallowed.
 * On success the parent refetches the list + stats and clears the selection.
 */

import { PICKER_MEMBER_STATUS } from '@/features/organization/api/use-members'
import { useMemo, useState } from 'react'
import { toast } from 'sonner'
import {
  UserPlus,
  ShieldAlert,
  Tag as TagIcon,
  TagsIcon,
  User,
  Building2,
  ChevronsUpDown,
  Check,
  Trash2,
} from 'lucide-react'
import {
  ConfirmDialog,
  ConfirmSample,
  irreversibleTypeToConfirm,
} from '@/components/confirm-dialog'
import { usePermissions, Permission } from '@/lib/permissions'
import { bulkDeleteAssetsSafely, reportBulkDelete } from '../../lib/safe-delete'
import { bulkActionsFor } from '../../lib/type-actions'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import useSWR from 'swr'
import { BulkActionBar } from '@/features/shared'
import { cn } from '@/lib/utils'
import { get } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useDebounce } from '@/hooks/use-debounce'
import { useTenant } from '@/context/tenant-provider'
import { useGroups } from '@/features/access-control/api/use-groups'
import { updateAsset } from '../../hooks/use-assets'
import { InventoryBusinessContextActions } from './inventory-business-context-actions'
import { addAssetOwner } from '../../hooks/use-asset-owners'
import {
  CRITICALITY_LABELS,
  OWNERSHIP_TYPE_LABELS,
  type Asset,
  type Criticality,
  type OwnershipType,
  type UpdateAssetInput,
} from '../../types/asset.types'
import { ASSET_CRITICALITY_LEVELS } from '@/lib/criticality'
import { useTranslation } from '@/context/i18n-provider'
import { AddToScopeAction } from '@/features/scope/components/add-to-scope-action'
import { ArchiveAssetsAction, MarkOutOfScopeAction } from './mark-out-of-scope-action'

interface BulkBarProps {
  selected: Asset[]
  canWrite: boolean
  onClear: () => void
  /** Called after a successful bulk mutation to refetch + drop the selection. */
  onDone: () => void
}

/** Run an async op over items in small concurrent batches; returns failures. */
async function runBulk<T>(items: T[], fn: (item: T) => Promise<unknown>): Promise<number> {
  const BATCH = 5
  let failed = 0
  for (let i = 0; i < items.length; i += BATCH) {
    const batch = items.slice(i, i + BATCH)
    const results = await Promise.allSettled(batch.map(fn))
    failed += results.filter((r) => r.status === 'rejected').length
  }
  return failed
}

/**
 * A full PUT body from the asset's CURRENT values plus the caller's overrides.
 * The update endpoint takes the whole asset, so echoing the existing fields
 * keeps a bulk criticality/tag change from clobbering name, scope, etc.
 */
function fullUpdate(a: Asset, overrides: Partial<UpdateAssetInput>): UpdateAssetInput {
  return {
    name: a.name,
    description: a.description,
    criticality: a.criticality,
    scope: a.scope,
    exposure: a.exposure,
    ownerRef: a.ownerRef,
    tags: a.tags,
    metadata: a.metadata,
    ...overrides,
  }
}

type PickerOption =
  | { kind: 'user'; id: string; label: string; sublabel?: string }
  | { kind: 'group'; id: string; label: string; sublabel?: string }

interface MemberWithUserResponse {
  user_id: string
  email: string
  name: string
}
interface MembersResponse {
  data: MemberWithUserResponse[]
  total: number
}

export function InventoryBulkBar({ selected, canWrite, onClear, onDone }: BulkBarProps) {
  const { t } = useTranslation()
  const count = selected.length
  const selectedNames = useMemo(() => selected.map((a) => a.name), [selected])
  const [dialog, setDialog] = useState<null | 'owner' | 'criticality' | 'tag' | 'removeTags'>(null)
  const [submitting, setSubmitting] = useState(false)

  // Set-criticality state
  const [criticality, setCriticality] = useState<Criticality>('high')

  // Add-tag state
  const [tag, setTag] = useState('')
  // Remove-tags state: the tags the selection carries (most common first)
  // and the ones ticked for removal.
  const [tagsToRemove, setTagsToRemove] = useState<string[]>([])
  const selectionTags = useMemo(() => {
    const counts = new Map<string, number>()
    for (const a of selected)
      for (const tg of a.tags ?? []) counts.set(tg, (counts.get(tg) ?? 0) + 1)
    return [...counts.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
  }, [selected])

  // Assign-owner state
  const [selectedOption, setSelectedOption] = useState<PickerOption | null>(null)
  const [ownershipType, setOwnershipType] = useState<OwnershipType>('primary')
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerSearch, setPickerSearch] = useState('')
  const debouncedSearch = useDebounce(pickerSearch, 250)

  const { currentTenant } = useTenant()
  const tenantSlug = currentTenant?.slug ?? null
  const ownerDialogOpen = dialog === 'owner'
  const { can } = usePermissions()
  const canDelete = can(Permission.AssetsDelete)
  // Type actions (repository Scan / Sync) for the selected assets they fit.
  const typeActions = bulkActionsFor(selected, t).filter((a) => a.permissions.every((p) => can(p)))
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [busy, setBusy] = useState(false)

  const runTypeAction = async (action: (typeof typeActions)[number]) => {
    setBusy(true)
    try {
      await action.run(selected.filter(action.applies))
      onDone()
    } finally {
      setBusy(false)
    }
  }

  const withFindings = selected.filter((a) => (a.findingCount ?? 0) > 0).length

  const deleteSelected = async () => {
    setBusy(true)
    try {
      const outcome = await bulkDeleteAssetsSafely(selected.map((a) => a.id))
      reportBulkDelete(outcome, onDone, t)
      setConfirmDelete(false)
      onDone()
    } catch (err) {
      toast.error(getErrorMessage(err, t('assets.bulk.deleteFailed', 'Failed to delete')))
    } finally {
      setBusy(false)
    }
  }

  const membersUrl = (() => {
    if (!ownerDialogOpen || !tenantSlug) return null
    // Owner picker: active members only (never a disabled or offboarded person).
    const params = new URLSearchParams({
      include: 'user',
      per_page: '50',
      status: PICKER_MEMBER_STATUS,
    })
    if (debouncedSearch.trim()) params.set('search', debouncedSearch.trim())
    return `/api/v1/tenants/${tenantSlug}/members?${params.toString()}`
  })()
  const { data: membersData, isLoading: membersLoading } = useSWR<MembersResponse>(
    membersUrl,
    (url: string) => get<MembersResponse>(url),
    { revalidateOnFocus: false, dedupingInterval: 30000, keepPreviousData: true }
  )
  const { groups: groupsData, isLoading: groupsLoading } = useGroups(
    ownerDialogOpen ? { search: debouncedSearch.trim() || undefined } : undefined
  )

  const userOptions: PickerOption[] = useMemo(
    () =>
      (membersData?.data ?? [])
        .map((m): PickerOption => ({
          kind: 'user',
          id: m.user_id,
          label: m.name?.trim() || m.email || t('assets.bulk.unnamedUser', '(unnamed user)'),
          sublabel: m.name?.trim() ? m.email : undefined,
        }))
        .filter((o) => o.id),
    [membersData, t]
  )
  const groupOptions: PickerOption[] = useMemo(
    () =>
      (groupsData ?? [])
        .map((g): PickerOption => ({
          kind: 'group',
          id: g.id,
          label: g.name,
          sublabel: g.description || undefined,
        }))
        .filter((o) => o.id),
    [groupsData]
  )
  const pickerLoading = membersLoading || groupsLoading
  const totalOptions = userOptions.length + groupOptions.length

  const closeDialog = () => {
    setDialog(null)
    setSelectedOption(null)
    setPickerSearch('')
    setTag('')
    setTagsToRemove([])
  }

  const reportResult = (label: string, failed: number) => {
    if (failed === 0) {
      toast.success(
        count === 1
          ? t('assets.bulk.resultOkOne', '{label} for 1 asset', { label })
          : t('assets.bulk.resultOkMany', '{label} for {count} assets', { label, count })
      )
    } else if (failed < count) {
      toast.warning(
        t('assets.bulk.resultPartial', '{label} for {done} of {count}; {failed} failed', {
          label,
          done: count - failed,
          count,
          failed,
        })
      )
    } else {
      toast.error(
        count === 1
          ? t('assets.bulk.resultFailOne', 'Failed to update 1 asset')
          : t('assets.bulk.resultFailMany', 'Failed to update {count} assets', { count })
      )
    }
  }

  const handleSetCriticality = async () => {
    setSubmitting(true)
    try {
      const failed = await runBulk(selected, (a) =>
        updateAsset(a.id, fullUpdate(a, { criticality }))
      )
      reportResult(
        t('assets.bulk.criticalitySet', 'Set criticality to {value}', {
          value: CRITICALITY_LABELS[criticality],
        }),
        failed
      )
      if (failed < count) {
        closeDialog()
        onDone()
      }
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('assets.bulk.criticalityFailed', 'Failed to set criticality'))
      )
    } finally {
      setSubmitting(false)
    }
  }

  const handleAddTag = async () => {
    const value = tag.trim()
    if (!value) {
      toast.error(t('assets.bulk.enterTag', 'Enter a tag'))
      return
    }
    setSubmitting(true)
    try {
      const failed = await runBulk(selected, (a) => {
        const nextTags = Array.from(new Set([...(a.tags ?? []), value]))
        return updateAsset(a.id, fullUpdate(a, { tags: nextTags }))
      })
      reportResult(t('assets.bulk.tagAdded', 'Added tag "{value}"', { value }), failed)
      if (failed < count) {
        closeDialog()
        onDone()
      }
    } catch (err) {
      toast.error(getErrorMessage(err, t('assets.bulk.tagFailed', 'Failed to add tag')))
    } finally {
      setSubmitting(false)
    }
  }

  const handleRemoveTags = async () => {
    if (tagsToRemove.length === 0) return
    // Only the assets that carry one of the tags are written.
    const affected = selected.filter((a) => (a.tags ?? []).some((tg) => tagsToRemove.includes(tg)))
    setSubmitting(true)
    try {
      const failed = await runBulk(affected, (a) =>
        updateAsset(
          a.id,
          fullUpdate(a, { tags: (a.tags ?? []).filter((tg) => !tagsToRemove.includes(tg)) })
        )
      )
      const vars = { count: affected.length, done: affected.length - failed, failed }
      if (failed === 0) {
        toast.success(t('assets.bulkTags.removed', 'Removed tags from {count} assets', vars))
      } else if (failed < affected.length) {
        toast.warning(
          t(
            'assets.bulkTags.removedPartly',
            'Removed tags from {done} of {count} assets; {failed} failed',
            vars
          )
        )
      } else {
        toast.error(t('assets.bulkTags.removeFailed', 'Failed to remove tags'))
      }
      if (failed < affected.length) {
        closeDialog()
        onDone()
      }
    } catch (err) {
      toast.error(getErrorMessage(err, t('assets.bulkTags.removeFailed', 'Failed to remove tags')))
    } finally {
      setSubmitting(false)
    }
  }

  const handleAssignOwner = async () => {
    if (!selectedOption) {
      toast.error(t('assets.bulk.selectOwner', 'Select a user or group'))
      return
    }
    setSubmitting(true)
    try {
      const failed = await runBulk(selected, (a) =>
        addAssetOwner(a.id, {
          userId: selectedOption.kind === 'user' ? selectedOption.id : undefined,
          groupId: selectedOption.kind === 'group' ? selectedOption.id : undefined,
          ownershipType,
        })
      )
      // A duplicate owner comes back as a rejection; treat "all failed" as a
      // hint rather than a hard error since some may already be owners.
      reportResult(
        t('assets.bulk.ownerAssigned', 'Assigned {name} as {role} owner', {
          name: selectedOption.label,
          role: OWNERSHIP_TYPE_LABELS[ownershipType].toLowerCase(),
        }),
        failed
      )
      if (failed < count) {
        closeDialog()
        onDone()
      }
    } catch (err) {
      toast.error(getErrorMessage(err, t('assets.bulk.ownerFailed', 'Failed to assign owner')))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <BulkActionBar count={count} onClear={onClear} noun="selected">
        {/* Scope is its own permission (scope:write), not assets:write. */}
        <AddToScopeAction names={selectedNames} onDone={onDone} />
        {/* Triage after the fact (research/124): each checks its own permission. */}
        <MarkOutOfScopeAction selected={selected} onDone={onDone} />
        <ArchiveAssetsAction selected={selected} onDone={onDone} />
        {canWrite ? (
          <>
            <Button variant="ghost" size="sm" onClick={() => setDialog('owner')}>
              <UserPlus className="me-2 h-4 w-4" />
              {t('assets.bulk.assignOwner', 'Assign owner')}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setDialog('criticality')}>
              <ShieldAlert className="me-2 h-4 w-4" />
              {t('assets.bulk.setCriticality', 'Set criticality')}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setDialog('tag')}>
              <TagIcon className="me-2 h-4 w-4" />
              {t('assets.bulk.addTag', 'Add tag')}
            </Button>
            {selectionTags.length > 0 && (
              <Button variant="ghost" size="sm" onClick={() => setDialog('removeTags')}>
                <TagsIcon className="me-2 h-4 w-4" />
                {t('assets.bulkTags.removeButton', 'Remove tags')}
              </Button>
            )}
            <InventoryBusinessContextActions selected={selected} onDone={onDone} />
            {typeActions.map((a) => (
              <Button
                key={a.id}
                variant="ghost"
                size="sm"
                disabled={busy}
                onClick={() => void runTypeAction(a)}
              >
                <a.icon className="me-2 h-4 w-4" />
                {a.label}
              </Button>
            ))}
            {canDelete && (
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive"
                disabled={busy}
                onClick={() => setConfirmDelete(true)}
              >
                <Trash2 className="me-2 h-4 w-4" />
                {t('assets.inv.delete', 'Delete')}
              </Button>
            )}
          </>
        ) : (
          <span className="whitespace-nowrap px-2 text-xs text-muted-foreground">
            {t('assets.bulk.readOnly', 'Read-only: assets:write is needed to change assets')}
          </span>
        )}
      </BulkActionBar>

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={
          count === 1
            ? t('confirm.asset.bulkDeleteTitleOne', 'Delete 1 asset?')
            : t('confirm.asset.bulkDeleteTitle', 'Delete {count} assets?', { count })
        }
        desc={t(
          'confirm.asset.bulkDeleteDescIrreversible',
          'This cannot be undone. They leave every list and are removed from their groups, owners, relationships and scope. An asset that has findings is not deleted: archive it instead to keep the finding history.'
        )}
        confirmText={
          busy
            ? t('confirm.deleting', 'Deleting…')
            : count === 1
              ? t('confirm.asset.bulkDeleteButtonOne', 'Delete 1 asset')
              : t('confirm.asset.bulkDeleteButton', 'Delete {count} assets', { count })
        }
        destructive
        isLoading={busy}
        typeToConfirm={irreversibleTypeToConfirm(selected.map((a) => a.name))}
        handleConfirm={deleteSelected}
      >
        <ConfirmSample names={selected.map((a) => a.name)} />
        {withFindings > 0 && (
          <p className="text-sm text-muted-foreground">
            {withFindings === 1
              ? t(
                  'confirm.asset.bulkWithFindingsOne',
                  '1 of them has findings, so it is not deleted; you can archive it afterwards.'
                )
              : t(
                  'confirm.asset.bulkWithFindings',
                  '{count} of them have findings, so they are not deleted; you can archive them afterwards.',
                  { count: withFindings }
                )}
          </p>
        )}
      </ConfirmDialog>

      {/* Set criticality */}
      <Dialog open={dialog === 'criticality'} onOpenChange={(o) => !o && closeDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('assets.bulk.setCriticality', 'Set criticality')}</DialogTitle>
            <DialogDescription>
              {count === 1
                ? t('assets.bulk.criticalityDescOne', 'Apply a criticality to 1 selected asset.')
                : t(
                    'assets.bulk.criticalityDescMany',
                    'Apply a criticality to {count} selected assets.',
                    {
                      count,
                    }
                  )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-2">
              <Label>{t('assets.badge.criticality', 'Criticality')}</Label>
              <Select value={criticality} onValueChange={(v) => setCriticality(v as Criticality)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ASSET_CRITICALITY_LEVELS.map((c) => (
                    <SelectItem key={c} value={c}>
                      {CRITICALITY_LABELS[c]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleSetCriticality} disabled={submitting}>
              {submitting
                ? t('assets.bulk.applying', 'Applying…')
                : t('assets.bulk.apply', 'Apply')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add tag */}
      <Dialog open={dialog === 'tag'} onOpenChange={(o) => !o && closeDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('assets.bulk.addTag', 'Add tag')}</DialogTitle>
            <DialogDescription>
              {count === 1
                ? t(
                    'assets.bulk.tagDescOne',
                    'Add a tag to 1 selected asset. Existing tags are kept.'
                  )
                : t(
                    'assets.bulk.tagDescMany',
                    'Add a tag to {count} selected assets. Existing tags are kept.',
                    {
                      count,
                    }
                  )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-2">
              <Label htmlFor="bulk-tag">{t('assets.bulk.tag', 'Tag')}</Label>
              <Input
                id="bulk-tag"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder={t('assets.bulk.tagPlaceholder', 'e.g. pci, external, team-payments')}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !submitting) handleAddTag()
                }}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleAddTag} disabled={submitting || !tag.trim()}>
              {submitting ? t('assets.bulk.adding', 'Adding…') : t('assets.bulk.addTag', 'Add tag')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Remove tags */}
      <Dialog open={dialog === 'removeTags'} onOpenChange={(o) => !o && closeDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('assets.bulkTags.removeTitle', 'Remove tags')}</DialogTitle>
            <DialogDescription>
              {t(
                'assets.bulkTags.removeDescription',
                'Remove the ticked tags from the {count} selected assets. Other tags are kept; system tags cannot be removed.',
                { count }
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div
              className="space-y-1"
              role="group"
              aria-label={t('assets.bulkTags.removeTitle', 'Remove tags')}
            >
              {selectionTags.map(([tg, n]) => {
                const id = `bulk-remove-tag-${tg}`
                return (
                  <label
                    key={tg}
                    htmlFor={id}
                    className="flex cursor-pointer items-center gap-2.5 rounded-md px-1.5 py-1 text-sm hover:bg-accent"
                  >
                    <Checkbox
                      id={id}
                      checked={tagsToRemove.includes(tg)}
                      onCheckedChange={(v) =>
                        setTagsToRemove((cur) =>
                          v === true ? [...cur, tg] : cur.filter((x) => x !== tg)
                        )
                      }
                    />
                    <span className="min-w-0 flex-1 truncate">{tg}</span>
                    <span className="text-xs tabular-nums text-muted-foreground">
                      {t('assets.bulkTags.onAssets', '{n} of {count}', { n, count })}
                    </span>
                  </label>
                )
              })}
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={handleRemoveTags}
              disabled={submitting || tagsToRemove.length === 0}
            >
              {submitting
                ? t('assets.bulkTags.removing', 'Removing…')
                : t('assets.bulkTags.removeConfirm', 'Remove {n} tags', { n: tagsToRemove.length })}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Assign owner */}
      <Dialog open={dialog === 'owner'} onOpenChange={(o) => !o && closeDialog()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('assets.bulk.assignOwner', 'Assign owner')}</DialogTitle>
            <DialogDescription>
              {count === 1
                ? t('assets.bulk.ownerDescOne', 'Assign a user or group to 1 selected asset.')
                : t(
                    'assets.bulk.ownerDescMany',
                    'Assign a user or group to {count} selected assets.',
                    {
                      count,
                    }
                  )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>{t('assets.inv.col.owner', 'Owner')}</Label>
                <Popover
                  open={pickerOpen}
                  onOpenChange={(open) => {
                    setPickerOpen(open)
                    if (!open) setPickerSearch('')
                  }}
                  modal
                >
                  <PopoverTrigger asChild>
                    <Button
                      variant="outline"
                      role="combobox"
                      aria-expanded={pickerOpen}
                      className="w-full min-w-0 justify-between overflow-hidden font-normal"
                      title={selectedOption?.label}
                    >
                      <span className="flex min-w-0 flex-1 items-center gap-2 text-start text-sm">
                        {selectedOption ? (
                          <>
                            {selectedOption.kind === 'user' ? (
                              <User className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                            ) : (
                              <Building2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                            )}
                            <span className="truncate">{selectedOption.label}</span>
                          </>
                        ) : (
                          <span className="text-muted-foreground">
                            {t('assets.bulk.selectOwnerPlaceholder', 'Select a user or group…')}
                          </span>
                        )}
                      </span>
                      <ChevronsUpDown className="ms-2 h-4 w-4 shrink-0 opacity-50" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent
                    className="w-[var(--radix-popover-trigger-width)] p-0"
                    align="start"
                  >
                    <Command shouldFilter={false}>
                      <CommandInput
                        value={pickerSearch}
                        onValueChange={setPickerSearch}
                        placeholder={t(
                          'assets.bulk.ownerSearch',
                          'Search by name, email, or group…'
                        )}
                      />
                      <CommandList>
                        {pickerLoading ? (
                          <div className="py-6 text-center text-sm text-muted-foreground">
                            {t('common.loading', 'Loading…')}
                          </div>
                        ) : totalOptions === 0 ? (
                          <CommandEmpty>
                            {debouncedSearch
                              ? t(
                                  'assets.bulk.ownerNoMatch',
                                  'No users or groups match "{query}".',
                                  {
                                    query: debouncedSearch,
                                  }
                                )
                              : t('assets.bulk.ownerNone', 'No users or groups available.')}
                          </CommandEmpty>
                        ) : (
                          <>
                            {userOptions.length > 0 && (
                              <CommandGroup heading={t('assets.bulk.users', 'Users')}>
                                {userOptions.map((option) => (
                                  <CommandItem
                                    key={`user:${option.id}`}
                                    value={`user:${option.id}`}
                                    onSelect={() => {
                                      setSelectedOption(option)
                                      setPickerOpen(false)
                                      setPickerSearch('')
                                    }}
                                    className="flex items-start gap-2"
                                  >
                                    <Check
                                      className={cn(
                                        'mt-1 h-4 w-4 shrink-0',
                                        selectedOption?.kind === 'user' &&
                                          selectedOption.id === option.id
                                          ? 'opacity-100'
                                          : 'opacity-0'
                                      )}
                                    />
                                    <User className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />
                                    <div className="min-w-0 flex-1">
                                      <p className="truncate text-sm">{option.label}</p>
                                      {option.sublabel && (
                                        <p className="truncate text-xs text-muted-foreground">
                                          {option.sublabel}
                                        </p>
                                      )}
                                    </div>
                                  </CommandItem>
                                ))}
                              </CommandGroup>
                            )}
                            {groupOptions.length > 0 && (
                              <CommandGroup heading={t('assets.bulk.groups', 'Groups')}>
                                {groupOptions.map((option) => (
                                  <CommandItem
                                    key={`group:${option.id}`}
                                    value={`group:${option.id}`}
                                    onSelect={() => {
                                      setSelectedOption(option)
                                      setPickerOpen(false)
                                      setPickerSearch('')
                                    }}
                                    className="flex items-start gap-2"
                                  >
                                    <Check
                                      className={cn(
                                        'mt-1 h-4 w-4 shrink-0',
                                        selectedOption?.kind === 'group' &&
                                          selectedOption.id === option.id
                                          ? 'opacity-100'
                                          : 'opacity-0'
                                      )}
                                    />
                                    <Building2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" />
                                    <div className="min-w-0 flex-1">
                                      <p className="truncate text-sm">{option.label}</p>
                                      {option.sublabel && (
                                        <p className="truncate text-xs text-muted-foreground">
                                          {option.sublabel}
                                        </p>
                                      )}
                                    </div>
                                  </CommandItem>
                                ))}
                              </CommandGroup>
                            )}
                          </>
                        )}
                      </CommandList>
                    </Command>
                  </PopoverContent>
                </Popover>
              </div>

              <div className="space-y-2">
                <Label>{t('assets.bulk.ownershipRole', 'Ownership role')}</Label>
                <Select
                  value={ownershipType}
                  onValueChange={(v) => setOwnershipType(v as OwnershipType)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(Object.entries(OWNERSHIP_TYPE_LABELS) as [OwnershipType, string][]).map(
                      ([value, label]) => (
                        <SelectItem key={value} value={value}>
                          {label}
                        </SelectItem>
                      )
                    )}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleAssignOwner} disabled={submitting || !selectedOption}>
              {submitting
                ? t('assets.bulk.assigning', 'Assigning…')
                : t('assets.bulk.assignOwner', 'Assign owner')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
