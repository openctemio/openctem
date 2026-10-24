'use client'

import { useMemo, useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Main } from '@/components/layout'
import {
  DataTable,
  DataTableColumnHeader,
  DataTableRowActions,
  EmptyState,
  GatedSectionTabs,
  PageHeader,
  PageStack,
  ErrorState,
  CappedNotice,
} from '@/features/shared'
import { THREAT_MODEL_SECTION_TABS } from '@/config/section-tabs'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Plus, Trash2, Lock, Target } from 'lucide-react'
import { post, del } from '@/lib/api/client'
import { useRegisterPages } from '@/lib/api/use-register-pages'
import { getErrorMessage } from '@/lib/api/error-handler'
import { profileTypeLabel } from '@/features/cycles/api'
import { Can, Permission } from '@/lib/permissions'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'

interface AttackerProfile {
  id: string
  name: string
  description: string
  profile_type: string
  capabilities: {
    network_access?: string
    credential_level?: string
    persistence?: boolean
    tools?: string[]
  }
  assumptions?: string
  is_default: boolean
  created_at: string
  updated_at: string
}

const PROFILE_TYPE_OPTIONS = [
  'external_unauth',
  'external_stolen_creds',
  'malicious_insider',
  'supplier_compromise',
  'custom',
] as const
const NETWORK_ACCESS_OPTIONS = ['external', 'internal', 'dmz'] as const
const CREDENTIAL_LEVEL_OPTIONS = ['none', 'user', 'admin'] as const

export default function AttackerProfilesPage() {
  const { t } = useTranslation()
  const {
    error: loadError,
    data: response,
    isLoading,
    mutate,
  } = useRegisterPages<AttackerProfile>('/api/v1/attacker-profiles?per_page=100')

  const profiles = response?.data ?? []

  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [deleteProfile, setDeleteProfile] = useState<AttackerProfile | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    profile_type: 'custom' as string,
    networkAccess: 'external',
    credentialLevel: 'none',
    persistence: false,
    tools: '',
    assumptions: '',
  })

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      profile_type: 'custom',
      networkAccess: 'external',
      credentialLevel: 'none',
      persistence: false,
      tools: '',
      assumptions: '',
    })
  }

  const [isCreating, setIsCreating] = useState(false)
  const handleCreate = async () => {
    if (isCreating) return
    if (!formData.name) {
      toast.error(t('attackerProfiles.nameRequired', 'Enter a profile name.'))
      return
    }
    setIsCreating(true)
    try {
      // The backend requires `capabilities` as a structured object, not a
      // string array — sending an array 400s and the create silently failed.
      await post('/api/v1/attacker-profiles', {
        name: formData.name,
        description: formData.description,
        profile_type: formData.profile_type,
        capabilities: {
          network_access: formData.networkAccess,
          credential_level: formData.credentialLevel,
          persistence: formData.persistence,
          tools: formData.tools
            .split(',')
            .map((c) => c.trim())
            .filter(Boolean),
        },
        assumptions: formData.assumptions || undefined,
      })
      await mutate()
      toast.success(t('attackerProfiles.created', 'Attacker profile created.'))
      setIsCreateOpen(false)
      resetForm()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('attackerProfiles.createFailed', 'Could not create the attacker profile.')
        )
      )
    } finally {
      setIsCreating(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteProfile) return
    try {
      await del(`/api/v1/attacker-profiles/${deleteProfile.id}`)
      await mutate()
      toast.success(t('attackerProfiles.deleted', 'Attacker profile deleted.'))
      setDeleteProfile(null)
    } catch {
      toast.error(t('attackerProfiles.deleteFailed', 'Could not delete the attacker profile.'))
    }
  }

  const columns = useMemo<ColumnDef<AttackerProfile>[]>(
    () => [
      {
        accessorKey: 'name',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('attackerProfiles.col.name', 'Name')} />
        ),
        cell: ({ row }) => {
          const profile = row.original
          return (
            <div className="flex items-center gap-2 font-medium">
              {profile.name}
              {profile.is_default && (
                <Lock
                  className="h-3 w-3 text-muted-foreground"
                  aria-label={t('attackerProfiles.builtIn', 'Built-in profile')}
                />
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'profile_type',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title={t('attackerProfiles.col.type', 'Type')} />
        ),
        cell: ({ row }) => {
          const profile = row.original
          return (
            <Badge variant="outline" className="font-normal">
              {t(
                `attackerProfiles.type.${profile.profile_type}`,
                profileTypeLabel(profile.profile_type)
              )}
            </Badge>
          )
        },
      },
      {
        id: 'capabilities',
        header: t('attackerProfiles.col.capabilities', 'Capabilities'),
        enableSorting: false,
        cell: ({ row }) => {
          const profile = row.original
          const caps = profile.capabilities ?? {}
          const items: string[] = []
          if (caps.network_access)
            items.push(
              t('attackerProfiles.cap.net', 'net: {value}', {
                value: t(`attackerProfiles.network.${caps.network_access}`, caps.network_access),
              })
            )
          if (caps.credential_level)
            items.push(
              t('attackerProfiles.cap.cred', 'cred: {value}', {
                value: t(
                  `attackerProfiles.credential.${caps.credential_level}`,
                  caps.credential_level
                ),
              })
            )
          if (caps.persistence) items.push(t('attackerProfiles.cap.persistent', 'persistent'))
          if (Array.isArray(caps.tools)) {
            items.push(...caps.tools.slice(0, 2))
          }
          return (
            <div className="flex flex-wrap gap-1">
              {items.slice(0, 3).map((cap, i) => (
                <Badge key={`${cap}-${i}`} variant="secondary" className="text-xs">
                  {cap}
                </Badge>
              ))}
              {items.length > 3 && (
                <Badge variant="secondary" className="text-xs">
                  +{items.length - 3}
                </Badge>
              )}
            </div>
          )
        },
      },
      {
        accessorKey: 'is_default',
        header: ({ column }) => (
          <DataTableColumnHeader
            column={column}
            title={t('attackerProfiles.col.default', 'Default')}
          />
        ),
        cell: ({ row }) =>
          row.original.is_default ? (
            <Badge variant="outline">{t('attackerProfiles.default', 'Default')}</Badge>
          ) : (
            <span className="text-muted-foreground text-sm">
              {t('attackerProfiles.type.custom', 'Custom')}
            </span>
          ),
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        cell: ({ row }) => {
          const profile = row.original
          // Built-in profiles are read-only.
          if (profile.is_default) return null
          return (
            <DataTableRowActions
              actions={[
                {
                  label: t('confirm.delete', 'Delete'),
                  icon: Trash2,
                  onClick: () => setDeleteProfile(profile),
                  destructive: true,
                  permission: Permission.AttackerProfilesWrite,
                },
              ]}
            />
          )
        },
      },
    ],
    [t]
  )

  return (
    <>
      <Main>
        <PageStack>
          <PageHeader
            title={t('attackerProfiles.title', 'Attacker profiles')}
            description={t(
              'attackerProfiles.description',
              'Threat actor profiles that exposure assessment and threat models reason about.'
            )}
          >
            <Can permission={Permission.AttackerProfilesWrite}>
              <Button size="sm" onClick={() => setIsCreateOpen(true)}>
                <Plus className="me-2 h-4 w-4" />
                {t('attackerProfiles.new', 'New profile')}
              </Button>
            </Can>
          </PageHeader>
          <GatedSectionTabs
            tabs={THREAT_MODEL_SECTION_TABS}
            label={t('threatModel.sections', 'Threat model sections')}
          />

          <div>
            {isLoading ? (
              <div className="space-y-2 rounded-xl border p-3">
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : loadError ? (
              <ErrorState
                title={t('attackerProfiles.loadError', 'attacker profiles')}
                error={loadError}
                onRetry={() => mutate()}
              />
            ) : profiles.length === 0 ? (
              <EmptyState
                icon={Target}
                title={t('attackerProfiles.emptyTitle', 'No attacker profiles yet')}
                description={t(
                  'attackerProfiles.emptyDescription',
                  'Create a profile to get started.'
                )}
              />
            ) : (
              <DataTable
                columns={columns}
                data={profiles}
                searchPlaceholder={t('attackerProfiles.search', 'Search profiles…')}
              />
            )}
          </div>
          <CappedNotice loaded={profiles.length} total={response?.total ?? 0} />
        </PageStack>
      </Main>

      <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('attackerProfiles.form.title', 'New attacker profile')}</DialogTitle>
            <DialogDescription>
              {t(
                'attackerProfiles.form.description',
                'Define a new threat actor profile for scoping.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">{t('attackerProfiles.form.name', 'Name')} *</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder={t(
                    'attackerProfiles.form.namePlaceholder',
                    'e.g. Financially motivated APT'
                  )}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">
                  {t('attackerProfiles.form.descriptionLabel', 'Description')}
                </Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder={t(
                    'attackerProfiles.form.descriptionPlaceholder',
                    'Describe the attacker profile…'
                  )}
                  rows={3}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="profile_type">
                  {t('attackerProfiles.form.type', 'Profile type')}
                </Label>
                <Select
                  value={formData.profile_type}
                  onValueChange={(value) =>
                    setFormData({
                      ...formData,
                      profile_type: value as AttackerProfile['profile_type'],
                    })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROFILE_TYPE_OPTIONS.map((o) => (
                      <SelectItem key={o} value={o}>
                        {t(`attackerProfiles.type.${o}`, profileTypeLabel(o))}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="network_access">
                    {t('attackerProfiles.form.networkAccess', 'Network access')}
                  </Label>
                  <Select
                    value={formData.networkAccess}
                    onValueChange={(value) => setFormData({ ...formData, networkAccess: value })}
                  >
                    <SelectTrigger id="network_access">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {NETWORK_ACCESS_OPTIONS.map((o) => (
                        <SelectItem key={o} value={o}>
                          {t(`attackerProfiles.network.${o}`, o)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="credential_level">
                    {t('attackerProfiles.form.credentialLevel', 'Credential level')}
                  </Label>
                  <Select
                    value={formData.credentialLevel}
                    onValueChange={(value) => setFormData({ ...formData, credentialLevel: value })}
                  >
                    <SelectTrigger id="credential_level">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {CREDENTIAL_LEVEL_OPTIONS.map((o) => (
                        <SelectItem key={o} value={o}>
                          {t(`attackerProfiles.credential.${o}`, o)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="persistence"
                  checked={formData.persistence}
                  onCheckedChange={(checked) =>
                    setFormData({ ...formData, persistence: checked as boolean })
                  }
                />
                <Label htmlFor="persistence" className="cursor-pointer">
                  {t('attackerProfiles.form.persistence', 'Can establish persistence')}
                </Label>
              </div>
              <div className="space-y-2">
                <Label htmlFor="tools">{t('attackerProfiles.form.tools', 'Tools')}</Label>
                <Input
                  id="tools"
                  value={formData.tools}
                  onChange={(e) => setFormData({ ...formData, tools: e.target.value })}
                  placeholder={t(
                    'attackerProfiles.form.toolsPlaceholder',
                    'Comma-separated, e.g. nmap, metasploit, commodity'
                  )}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="assumptions">
                  {t('attackerProfiles.form.assumptions', 'Assumptions')}
                </Label>
                <Textarea
                  id="assumptions"
                  value={formData.assumptions}
                  onChange={(e) => setFormData({ ...formData, assumptions: e.target.value })}
                  placeholder={t(
                    'attackerProfiles.form.assumptionsPlaceholder',
                    'What this threat actor is assumed to be able to do'
                  )}
                />
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsCreateOpen(false)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button onClick={handleCreate} disabled={isCreating}>
              {t('attackerProfiles.form.create', 'Create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleteProfile}
        onOpenChange={(open) => !open && setDeleteProfile(null)}
        title={t('confirm.attackerProfile.deleteTitle', 'Delete the attacker profile "{name}"?', {
          name: deleteProfile?.name ?? '',
        })}
        desc={t(
          'confirm.attackerProfile.deleteDesc',
          'It is removed from every cycle that uses it. This cannot be undone.'
        )}
        confirmText={t('confirm.delete', 'Delete')}
        destructive
        handleConfirm={handleDelete}
      />
    </>
  )
}
