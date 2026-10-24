'use client'

import { useState, useMemo, useCallback, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, ConfirmSample } from '@/components/confirm-dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetBody,
  SheetTitle,
  SheetFooter,
} from '@/components/ui/sheet'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import {
  Shield,
  Search,
  ChevronRight,
  Eye,
  Pencil,
  Trash2,
  Loader2,
  Check,
  X,
  Database,
  Eraser,
  Save,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  useUpdateRole,
  useTenantPermissionModules,
  type Role,
  type PermissionModule,
} from '@/features/access-control'

interface EditRoleSheetProps {
  role: Role | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

// Permission type colors
const permissionTypeConfig: Record<
  string,
  { color: string; bgColor: string; icon: React.ElementType }
> = {
  read: { color: 'text-emerald-600', bgColor: 'bg-emerald-50 dark:bg-emerald-950', icon: Eye },
  write: { color: 'text-blue-600', bgColor: 'bg-blue-50 dark:bg-blue-950', icon: Pencil },
  delete: { color: 'text-red-600', bgColor: 'bg-red-50 dark:bg-red-950', icon: Trash2 },
}

function getPermissionType(permissionId: string): string {
  // Extract the action (last part after the last colon)
  // Permission format: {module}:{subfeature}:{action}
  const action = permissionId.split(':').pop() || ''

  if (action === 'delete' || action === 'remove') return 'delete'
  if (
    [
      'write',
      'create',
      'update',
      'manage',
      'assign',
      'trigger',
      'cancel',
      'schedule',
      'invite',
      'bulk',
      'export',
    ].includes(action)
  )
    return 'write'
  return 'read'
}

export function EditRoleSheet({ role, open, onOpenChange, onSuccess }: EditRoleSheetProps) {
  const { t } = useTranslation()
  const { updateRole, isUpdating } = useUpdateRole(role?.id || null)
  const { modules: permissionModules, isLoading: isLoadingModules } = useTenantPermissionModules(
    true,
    {
      forCustomRole: true,
    }
  )

  // Form state
  const [form, setForm] = useState({
    name: '',
    description: '',
    hasFullDataAccess: false,
    permissions: [] as string[],
  })

  // UI state
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set())

  // Initialize form when role changes
  useEffect(() => {
    if (role && open) {
      setForm({
        name: role.name,
        description: role.description || '',
        hasFullDataAccess: role.has_full_data_access,
        permissions: [...role.permissions],
      })
      setSearchQuery('')
      setExpandedModules(new Set())
    }
  }, [role, open])

  // Reset form when sheet closes
  const handleOpenChange = (open: boolean) => {
    if (!open) {
      setSearchQuery('')
      setExpandedModules(new Set())
    }
    onOpenChange(open)
  }

  // Filter modules based on search
  const filteredModules = useMemo(() => {
    if (!searchQuery.trim()) return permissionModules

    const query = searchQuery.toLowerCase()
    return permissionModules
      .map((module) => ({
        ...module,
        permissions: module.permissions.filter(
          (p) =>
            p.name.toLowerCase().includes(query) ||
            p.id.toLowerCase().includes(query) ||
            p.description?.toLowerCase().includes(query)
        ),
      }))
      .filter(
        (module) => module.permissions.length > 0 || module.name.toLowerCase().includes(query)
      )
  }, [permissionModules, searchQuery])

  // Toggle module expansion
  const toggleModule = (moduleId: string) => {
    setExpandedModules((prev) => {
      const next = new Set(prev)
      if (next.has(moduleId)) {
        next.delete(moduleId)
      } else {
        next.add(moduleId)
      }
      return next
    })
  }

  // Toggle single permission
  const togglePermission = useCallback((permissionId: string) => {
    setForm((prev) => ({
      ...prev,
      permissions: prev.permissions.includes(permissionId)
        ? prev.permissions.filter((p) => p !== permissionId)
        : [...prev.permissions, permissionId],
    }))
  }, [])

  // Toggle all permissions in a module
  const toggleModulePermissions = useCallback((module: PermissionModule, checked: boolean) => {
    const modulePermissionIds = module.permissions.map((p) => p.id)
    setForm((prev) => ({
      ...prev,
      permissions: checked
        ? [...new Set([...prev.permissions, ...modulePermissionIds])]
        : prev.permissions.filter((p) => !modulePermissionIds.includes(p)),
    }))
  }, [])

  // Quick actions
  const selectAllRead = useCallback(() => {
    const readPermissions = permissionModules.flatMap((m) =>
      m.permissions.filter((p) => getPermissionType(p.id) === 'read').map((p) => p.id)
    )
    setForm((prev) => ({
      ...prev,
      permissions: [...new Set([...prev.permissions, ...readPermissions])],
    }))
  }, [permissionModules])

  const selectAllWrite = useCallback(() => {
    const writePermissions = permissionModules.flatMap((m) =>
      m.permissions.filter((p) => getPermissionType(p.id) === 'write').map((p) => p.id)
    )
    setForm((prev) => ({
      ...prev,
      permissions: [...new Set([...prev.permissions, ...writePermissions])],
    }))
  }, [permissionModules])

  const clearAllPermissions = useCallback(() => {
    setForm((prev) => ({ ...prev, permissions: [] }))
  }, [])

  // Group selected permissions by module for preview
  const groupedSelectedPermissions = useMemo(() => {
    const groups: Record<string, { module: PermissionModule; permissions: string[] }> = {}

    for (const permModule of permissionModules) {
      const selected = permModule.permissions
        .filter((p) => form.permissions.includes(p.id))
        .map((p) => p.id)

      if (selected.length > 0) {
        groups[permModule.id] = { module: permModule, permissions: selected }
      }
    }

    return groups
  }, [permissionModules, form.permissions])

  // Check if form has changes
  const hasChanges = useMemo(() => {
    if (!role) return false

    const nameChanged = form.name !== role.name
    const descChanged = form.description !== (role.description || '')
    const accessChanged = form.hasFullDataAccess !== role.has_full_data_access

    const originalPerms = new Set(role.permissions)
    const currentPerms = new Set(form.permissions)
    const permsChanged =
      originalPerms.size !== currentPerms.size ||
      [...originalPerms].some((p) => !currentPerms.has(p))

    return nameChanged || descChanged || accessChanged || permsChanged
  }, [role, form])

  // Widening a role (permissions added, or full data access turned on) reaches
  // everyone who holds it at once, so it asks first. Narrowing saves directly.
  const [confirmWiden, setConfirmWiden] = useState(false)
  const addedPermissions = useMemo(
    () => (role ? form.permissions.filter((p) => !role.permissions.includes(p)) : []),
    [role, form.permissions]
  )
  const gainsFullData = !!role && form.hasFullDataAccess && !role.has_full_data_access
  const widens = addedPermissions.length > 0 || gainsFullData

  // Handle update
  const handleUpdate = async () => {
    setConfirmWiden(false)
    if (!role) return

    if (!form.name.trim()) {
      toast.error(t('org.roleSheet.nameRequired', 'Enter a role name'))
      return
    }

    try {
      await updateRole({
        name: form.name,
        // "" clears the description (absent would mean unchanged).
        description: form.description.trim(),
        has_full_data_access: form.hasFullDataAccess,
        permissions: form.permissions,
      })
      toast.success(t('org.roleSheet.updated', 'Role "{name}" updated', { name: form.name }))
      handleOpenChange(false)
      onSuccess?.()
    } catch (error) {
      toast.error(getErrorMessage(error, t('org.roleSheet.updateFailed', 'Failed to update role')))
    }
  }

  // Get module selection state
  const getModuleSelectionState = (module: PermissionModule) => {
    const modulePermissionIds = module.permissions.map((p) => p.id)
    const selectedCount = form.permissions.filter((p) => modulePermissionIds.includes(p)).length
    const total = modulePermissionIds.length

    return {
      selectedCount,
      total,
      allSelected: total > 0 && selectedCount === total,
      someSelected: selectedCount > 0 && selectedCount < total,
    }
  }

  if (!role) return null

  return (
    <Sheet open={open} onOpenChange={handleOpenChange}>
      <SheetContent className="sm:max-w-4xl">
        {/* Header */}
        <SheetHeader>
          <div className="flex items-center gap-3">
            <div className="rounded-full bg-blue-100 dark:bg-blue-900 p-2">
              <Pencil className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <SheetTitle>{t('org.roleSheet.editTitle', 'Edit role')}</SheetTitle>
              <SheetDescription>
                {t('org.roleSheet.editDesc', 'Update role settings and permissions')}
              </SheetDescription>
            </div>
          </div>
        </SheetHeader>

        {/* Content - Two columns */}
        <SheetBody className="flex overflow-hidden p-0 sm:p-0">
          {/* Left Column - Form */}
          <div className="flex-1 flex flex-col min-h-0 border-r">
            <ScrollArea className="flex-1 h-full">
              <div className="p-6 space-y-6">
                {/* Basic Info */}
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="role-name">{t('org.roleSheet.roleName', 'Role name')}</Label>
                    <Input
                      id="role-name"
                      placeholder={t(
                        'org.roleSheet.roleNamePlaceholder',
                        'e.g., Security analyst, DevOps lead'
                      )}
                      value={form.name}
                      onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
                    />
                    <p className="text-xs text-muted-foreground">
                      Slug: <code className="bg-muted px-1 rounded">{role.slug}</code> (cannot be
                      changed)
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="role-description">
                      {t('org.roleSheet.descLabel', 'Description (optional)')}
                    </Label>
                    <Textarea
                      id="role-description"
                      placeholder={t(
                        'org.roleSheet.descPlaceholder',
                        'Describe what this role can do...'
                      )}
                      value={form.description}
                      onChange={(e) =>
                        setForm((prev) => ({ ...prev, description: e.target.value }))
                      }
                      rows={2}
                    />
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-lg border bg-muted/30">
                    <div className="flex items-center gap-3">
                      <Database className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <Label className="text-sm font-medium">
                          {t('org.roleSheet.fullData', 'Full data access')}
                        </Label>
                        <p className="text-xs text-muted-foreground">
                          {t(
                            'org.roleSheet.fullDataHint',
                            'Access all data regardless of team membership'
                          )}
                        </p>
                      </div>
                    </div>
                    <Switch
                      aria-label={t('org.roleSheet.fullData', 'Full data access')}
                      checked={form.hasFullDataAccess}
                      onCheckedChange={(checked) =>
                        setForm((prev) => ({ ...prev, hasFullDataAccess: checked }))
                      }
                    />
                  </div>
                </div>

                {/* Permissions Section */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <Label className="text-base font-semibold">
                      {t('org.roleSheet.permissions', 'Permissions')}
                    </Label>
                    <Badge variant="secondary" className="font-mono">
                      {t('org.roleSheet.selectedCount', '{count} selected', {
                        count: form.permissions.length,
                      })}
                    </Badge>
                  </div>

                  {/* Search */}
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder={t('org.roleSheet.searchPlaceholder', 'Search permissions...')}
                      aria-label={t('org.roleSheet.searchLabel', 'Search permissions')}
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="ps-9"
                    />
                  </div>

                  {/* Quick Actions */}
                  <div className="flex flex-wrap gap-2">
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button variant="outline" size="sm" onClick={selectAllRead}>
                            <Eye className="me-1.5 h-3.5 w-3.5 text-emerald-600" />
                            {t('org.roleSheet.allRead', 'All read')}
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                          {t('org.roleSheet.allReadHint', 'Select all read permissions')}
                        </TooltipContent>
                      </Tooltip>

                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button variant="outline" size="sm" onClick={selectAllWrite}>
                            <Pencil className="me-1.5 h-3.5 w-3.5 text-blue-600" />
                            {t('org.roleSheet.allWrite', 'All write')}
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                          {t('org.roleSheet.allWriteHint', 'Select all write permissions')}
                        </TooltipContent>
                      </Tooltip>

                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={clearAllPermissions}
                            disabled={form.permissions.length === 0}
                          >
                            <Eraser className="me-1.5 h-3.5 w-3.5" />
                            {t('org.roleSheet.clear', 'Clear')}
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                          {t('org.roleSheet.clearHint', 'Clear all selected permissions')}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </div>

                  {/* Permission Modules */}
                  {isLoadingModules ? (
                    <div className="flex items-center justify-center py-12">
                      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                    </div>
                  ) : filteredModules.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <Search className="h-8 w-8 text-muted-foreground/50 mb-2" />
                      <p className="text-muted-foreground text-sm">
                        {t('org.roleSheet.noneFound', 'No permissions found')}
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {filteredModules.map((module) => {
                        const { selectedCount, total, allSelected, someSelected } =
                          getModuleSelectionState(module)
                        const isExpanded = expandedModules.has(module.id) || searchQuery.length > 0

                        return (
                          <Collapsible
                            key={module.id}
                            open={isExpanded}
                            onOpenChange={() => toggleModule(module.id)}
                          >
                            <div className="rounded-lg border bg-card">
                              {/* Module Header */}
                              <div className="flex items-center gap-2 p-3">
                                <Checkbox
                                  checked={allSelected || (someSelected && 'indeterminate')}
                                  onCheckedChange={(checked) =>
                                    toggleModulePermissions(module, !!checked)
                                  }
                                  onClick={(e) => e.stopPropagation()}
                                />
                                <CollapsibleTrigger asChild>
                                  <button className="flex-1 flex items-center gap-2 text-start hover:bg-muted/50 rounded -m-1 p-1">
                                    <ChevronRight
                                      className={cn(
                                        'h-4 w-4 text-muted-foreground transition-transform',
                                        isExpanded && 'rotate-90'
                                      )}
                                    />
                                    <span className="font-medium text-sm">{module.name}</span>
                                    <Badge
                                      variant={selectedCount > 0 ? 'default' : 'secondary'}
                                      className="text-xs font-mono ms-auto"
                                    >
                                      {selectedCount}/{total}
                                    </Badge>
                                  </button>
                                </CollapsibleTrigger>
                              </div>

                              {/* Module Permissions */}
                              <CollapsibleContent>
                                <div className="px-3 pb-3 pt-1">
                                  {module.description && (
                                    <p className="text-xs text-muted-foreground mb-3 ms-6">
                                      {module.description}
                                    </p>
                                  )}
                                  <div className="flex flex-wrap gap-2 ms-6">
                                    {module.permissions.map((permission) => {
                                      const type = getPermissionType(permission.id)
                                      const config = permissionTypeConfig[type]
                                      const isSelected = form.permissions.includes(permission.id)
                                      const Icon = config.icon

                                      return (
                                        <TooltipProvider key={permission.id}>
                                          <Tooltip>
                                            <TooltipTrigger asChild>
                                              <button
                                                onClick={() => togglePermission(permission.id)}
                                                className={cn(
                                                  'inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium transition-all border',
                                                  isSelected
                                                    ? `${config.bgColor} ${config.color} border-current`
                                                    : 'bg-muted/50 text-muted-foreground border-transparent hover:bg-muted'
                                                )}
                                              >
                                                {isSelected ? (
                                                  <Check className="h-3 w-3" />
                                                ) : (
                                                  <Icon className="h-3 w-3" />
                                                )}
                                                {permission.name}
                                              </button>
                                            </TooltipTrigger>
                                            <TooltipContent side="top" className="max-w-xs">
                                              <p className="font-mono text-xs">{permission.id}</p>
                                              {permission.description && (
                                                <p className="text-xs mt-1">
                                                  {permission.description}
                                                </p>
                                              )}
                                            </TooltipContent>
                                          </Tooltip>
                                        </TooltipProvider>
                                      )
                                    })}
                                  </div>
                                </div>
                              </CollapsibleContent>
                            </div>
                          </Collapsible>
                        )
                      })}
                    </div>
                  )}
                </div>
              </div>
            </ScrollArea>
          </div>

          {/* Right Column - Preview */}
          <div className="w-80 flex flex-col min-h-0 bg-muted/30">
            <div className="p-4 border-b shrink-0">
              <h3 className="font-semibold text-sm">{t('org.roleSheet.preview', 'Preview')}</h3>
            </div>
            <ScrollArea className="flex-1 h-full">
              <div className="p-4 space-y-4">
                {/* Role Info Preview */}
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <Shield className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="font-medium text-sm">
                        {form.name || (
                          <span className="text-muted-foreground italic">
                            {t('org.roleSheet.enterName', 'Enter role name...')}
                          </span>
                        )}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {t('org.roleSheet.permCount', '{count} permissions', {
                          count: form.permissions.length,
                        })}
                      </p>
                    </div>
                  </div>
                  {form.description && (
                    <p className="text-xs text-muted-foreground">{form.description}</p>
                  )}
                  {form.hasFullDataAccess && (
                    <Badge variant="secondary" className="text-xs">
                      <Database className="me-1 h-3 w-3" />
                      {t('org.roleSheet.fullData', 'Full data access')}
                    </Badge>
                  )}
                </div>

                {/* Changes indicator */}
                {hasChanges && (
                  <div className="p-2 rounded-lg bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800">
                    <p className="text-xs text-amber-700 dark:text-amber-300 font-medium">
                      {t('org.roleSheet.unsaved', 'Unsaved changes')}
                    </p>
                  </div>
                )}

                {/* Selected Permissions */}
                {form.permissions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-8 text-center">
                    <Shield className="h-8 w-8 text-muted-foreground/30 mb-2" />
                    <p className="text-xs text-muted-foreground">
                      {t('org.roleSheet.noneSelected', 'No permissions selected')}
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                      {t('org.roleSheet.selectedPermissions', 'Selected permissions')}
                    </p>
                    {Object.entries(groupedSelectedPermissions).map(
                      ([moduleId, { module, permissions }]) => (
                        <div key={moduleId} className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <p className="text-xs font-medium">{module.name}</p>
                            <Badge variant="outline" className="text-xs h-5">
                              {permissions.length}
                            </Badge>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {permissions.map((permId) => {
                              const perm = module.permissions.find((p) => p.id === permId)
                              const type = getPermissionType(permId)
                              const config = permissionTypeConfig[type]

                              return (
                                <button
                                  key={permId}
                                  onClick={() => togglePermission(permId)}
                                  className={cn(
                                    'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs',
                                    config.bgColor,
                                    config.color,
                                    'hover:opacity-80 transition-opacity'
                                  )}
                                >
                                  <span>{perm?.name || permId.split(':')[1]}</span>
                                  <X className="h-2.5 w-2.5" />
                                </button>
                              )
                            })}
                          </div>
                        </div>
                      )
                    )}
                  </div>
                )}
              </div>
            </ScrollArea>
          </div>
        </SheetBody>

        {/* Footer */}
        <SheetFooter>
          <Button variant="ghost" onClick={() => handleOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={() => (widens ? setConfirmWiden(true) : void handleUpdate())}
            disabled={isUpdating || !form.name.trim() || !hasChanges}
          >
            {isUpdating ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
            ) : (
              <Save className="me-2 h-4 w-4" />
            )}
            {t('org.roleSheet.saveChanges', 'Save changes')}
          </Button>
        </SheetFooter>
      </SheetContent>
      <ConfirmDialog
        open={confirmWiden}
        onOpenChange={setConfirmWiden}
        title={t('confirm.role.widenTitle', 'Give everyone with {name} more access?', {
          name: role?.name ?? '',
        })}
        desc={
          <>
            {addedPermissions.length > 0 &&
              t(
                'confirm.role.widenPermissions',
                'This role gains {count} permissions. Everyone who holds it has them as soon as you save.',
                { count: addedPermissions.length }
              )}{' '}
            {gainsFullData &&
              t(
                'confirm.role.widenFullData',
                'It also gives them access to every asset, not only their own scope.'
              )}{' '}
            {t(
              'confirm.role.widenNote',
              'The change is recorded in the audit log. You can narrow the role again later.'
            )}
          </>
        }
        confirmText={t('confirm.role.widenConfirm', 'Save and widen role')}
        handleConfirm={handleUpdate}
      >
        {addedPermissions.length > 0 && (
          <ConfirmSample names={addedPermissions} total={addedPermissions.length} />
        )}
      </ConfirmDialog>
    </Sheet>
  )
}
