'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from '@/components/link'
import { Building, Lock, Upload, UserCog } from 'lucide-react'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { DangerZone, DangerZoneItem, PageHeader, SettingsSaveBar } from '@/features/shared'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { useAppHost } from '@/hooks/use-app-origin'
import { useUrlFilter } from '@/hooks/use-url-param'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate, usePermissions } from '@/lib/permissions'
import { safeImageSrc } from '@/lib/safe-href'
import { OrganizationRegion } from '@/features/tenant/components/region-note'
import {
  useTenantSettings,
  useUpdateBrandingSettings,
  useUpdateGeneralSettings,
  useUpdateTenant,
} from '../api/use-tenant-settings'
import { useTenantLogo } from '../hooks/use-tenant-logo'
import {
  planGeneralSave,
  planHasChanges,
  type GeneralSettingsValues,
} from '../lib/general-save-plan'
import { DeleteOrganizationItem } from './delete-organization'
import { SettingsLoadError, SettingsLoading } from './settings-load-state'
import { StorageConfigCard } from './storage-config-card'

const GENERAL_TABS = ['general', 'storage'] as const

const EMPTY_GENERAL: GeneralSettingsValues = {
  timezone: 'UTC',
  language: 'en',
  industry: '',
  website: '',
}

/** Downscale an image file to at most 200×200 px, as a JPEG data URL. */
function readLogo(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error)
    reader.onload = (ev) => {
      const img = new Image()
      img.onerror = () => reject(new Error('image'))
      img.onload = () => {
        const max = 200
        let w = img.width
        let h = img.height
        if (w > max) {
          h = (h * max) / w
          w = max
        }
        if (h > max) {
          w = (w * max) / h
          h = max
        }
        const canvas = document.createElement('canvas')
        canvas.width = w
        canvas.height = h
        canvas.getContext('2d')?.drawImage(img, 0, 0, w, h)
        resolve(canvas.toDataURL('image/jpeg', 0.85))
      }
      img.src = ev.target?.result as string
    }
    reader.readAsDataURL(file)
  })
}

/**
 * Organization › General: the organization's name, URL, logo and website
 * (one sticky Save for the tab), the file storage tab, and the owner's
 * danger zone (transfer ownership, delete). Leaving an organization is in
 * My account › Profile, where every member can reach it.
 */
export function GeneralSettings() {
  const { t } = useTranslation()
  const appHost = useAppHost()
  const [tabParam, setTabParam] = useUrlFilter('tab', 'general')
  const activeTab = (GENERAL_TABS as readonly string[]).includes(tabParam) ? tabParam : 'general'

  const { currentTenant, updateCurrentTenant, refreshTenants } = useTenant()
  const tenantId = currentTenant?.id
  const { isOwner } = usePermissions()
  const owner = isOwner()

  // Controls follow the API route gates (permission + role), so a custom
  // role with team:update but not admin never sees a Save that 403s.
  const canUpdateTenant = useCanMutate(
    'PATCH /api/v1/tenants/{tenant}',
    'PATCH /api/v1/tenants/{tenant}/settings/general',
    'PATCH /api/v1/tenants/{tenant}/settings/branding'
  )

  const { settings, isLoading, isError, error, mutate } = useTenantSettings(tenantId)
  const { updateTenant, isUpdating: savingTenant } = useUpdateTenant(tenantId)
  const { updateGeneralSettings, isUpdating: savingGeneral } = useUpdateGeneralSettings(tenantId)
  const { updateBrandingSettings, isUpdating: savingBranding } = useUpdateBrandingSettings(tenantId)
  const saving = savingTenant || savingGeneral || savingBranding

  const savedGeneral = useMemo<GeneralSettingsValues>(
    () => ({
      timezone: settings?.general.timezone || 'UTC',
      language: settings?.general.language || 'en',
      industry: settings?.general.industry || '',
      website: settings?.general.website || '',
    }),
    [settings]
  )
  const branding = useMemo(
    () => ({
      primary_color: settings?.branding.primary_color || '#3B82F6',
      logo_dark_url: settings?.branding.logo_dark_url || '',
      logo_data: settings?.branding.logo_data || null,
    }),
    [settings]
  )

  const [orgInfo, setOrgInfo] = useState({ name: '', slug: '' })
  const [general, setGeneral] = useState<GeneralSettingsValues>(EMPTY_GENERAL)
  // A logo picked or removed but not saved yet: undefined = unchanged,
  // a data URL = replace, null = remove.
  const [logoDraft, setLogoDraft] = useState<string | null | undefined>(undefined)
  const { logoSrc, updateLogo } = useTenantLogo(
    tenantId,
    settings?.branding.logo_data,
    currentTenant?.logo_url
  )

  const reset = useCallback(() => {
    setOrgInfo({ name: currentTenant?.name || '', slug: currentTenant?.slug || '' })
    setGeneral(savedGeneral)
    setLogoDraft(undefined)
  }, [currentTenant?.name, currentTenant?.slug, savedGeneral])

  // Load the saved values into the form (and again after every save).
  useEffect(() => {
    reset()
  }, [reset])

  const plan = useMemo(
    () =>
      planGeneralSave({
        orgInfo,
        current: currentTenant,
        generalForm: general,
        savedGeneral: settings ? savedGeneral : null,
        branding,
        logoDraft,
      }),
    [orgInfo, currentTenant, general, settings, savedGeneral, branding, logoDraft]
  )
  const dirty = planHasChanges(plan)

  const handleSave = async () => {
    if (!planHasChanges(plan)) return
    try {
      if (plan.orgChanges) {
        await updateTenant(plan.orgChanges)
        updateCurrentTenant(plan.orgChanges)
        refreshTenants()
      }
      if (plan.general) {
        const result = await updateGeneralSettings(plan.general)
        if (result) await mutate(result, { revalidate: false })
      }
      if (plan.branding) {
        const result = await updateBrandingSettings(plan.branding)
        if (result) {
          await mutate(result, { revalidate: false })
          updateLogo(plan.branding.logo_data)
        }
        setLogoDraft(undefined)
      }
      toast.success(t('org.general.saved', 'Organization settings saved'))
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('org.general.saveFailed', 'Could not save the organization settings')
        )
      )
    }
  }

  const header = (
    <PageHeader
      title={t('org.general.title', 'General')}
      description={t(
        'org.general.desc',
        "Your organization's name, logo and file storage, and the owner's danger zone."
      )}
    />
  )
  if (isLoading) return <SettingsLoading header={header} />
  if (isError)
    return (
      <SettingsLoadError header={header} message={error?.message} onRetry={() => void mutate()} />
    )

  const logoPreview =
    logoDraft === null ? undefined : safeImageSrc(logoDraft ?? (branding.logo_data || logoSrc))

  return (
    <Main>
      {header}
      <Tabs
        value={activeTab}
        onValueChange={(v) => setTabParam(v === 'general' ? '' : v)}
        className="mt-4"
      >
        <TabsList className="overflow-x-auto">
          <TabsTrigger value="general">
            <Building className="me-2 h-4 w-4" aria-hidden />
            {t('org.general.tab.general', 'General')}
          </TabsTrigger>
          <TabsTrigger value="storage">
            <Upload className="me-2 h-4 w-4" aria-hidden />
            {t('org.general.tab.storage', 'File storage')}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="mt-5 space-y-5">
          <Card id="org-profile">
            <CardHeader>
              <CardTitle>{t('org.general.profile', 'Organization information')}</CardTitle>
              <CardDescription>
                {t('org.general.profileDesc', 'How your organization is named and recognised.')}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col gap-8 lg:flex-row">
                <div className="flex flex-col items-center gap-3 lg:items-start lg:border-e lg:pe-8">
                  <Avatar className="h-24 w-24 ring-2 ring-border">
                    <AvatarImage src={logoPreview} alt="" />
                    <AvatarFallback className="bg-primary/10 text-3xl">
                      {currentTenant?.name?.charAt(0) || 'O'}
                    </AvatarFallback>
                  </Avatar>
                  {canUpdateTenant ? (
                    <div className="flex flex-col items-center gap-1">
                      <Button variant="outline" size="sm" asChild>
                        <label className="cursor-pointer">
                          <Upload className="h-4 w-4" aria-hidden />
                          {t('org.general.logoUpload', 'Upload logo')}
                          <input
                            type="file"
                            accept="image/png,image/jpeg,image/webp"
                            className="sr-only"
                            onChange={async (e) => {
                              const file = e.target.files?.[0]
                              e.target.value = ''
                              if (!file) return
                              try {
                                setLogoDraft(await readLogo(file))
                              } catch {
                                toast.error(
                                  t('org.general.logoUnreadable', 'That image could not be read')
                                )
                              }
                            }}
                          />
                        </label>
                      </Button>
                      <p className="text-center text-xs text-muted-foreground">
                        {t(
                          'org.general.logoHint',
                          'PNG, JPEG or WebP, shown at up to 200 × 200 px'
                        )}
                      </p>
                      {logoDraft === undefined && (logoSrc || currentTenant?.logo_url) && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
                          onClick={() => setLogoDraft(null)}
                        >
                          {t('org.general.logoRemove', 'Remove logo')}
                        </Button>
                      )}
                      {logoDraft !== undefined && (
                        <p className="text-xs text-muted-foreground">
                          {logoDraft === null
                            ? t('org.general.logoWillRemove', 'The logo is removed when you save.')
                            : t(
                                'org.general.logoWillReplace',
                                'The new logo is used when you save.'
                              )}
                        </p>
                      )}
                    </div>
                  ) : (
                    <p className="text-center text-xs text-muted-foreground">
                      {t('org.general.logoLocked', 'Only administrators can change the logo.')}
                    </p>
                  )}
                </div>

                <div className="flex-1 space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="org-name">{t('org.general.name', 'Organization name')}</Label>
                      <Input
                        id="org-name"
                        value={orgInfo.name}
                        onChange={(e) => setOrgInfo((p) => ({ ...p, name: e.target.value }))}
                        disabled={!canUpdateTenant}
                        maxLength={100}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="org-slug">{t('org.general.slug', 'URL slug')}</Label>
                      <div className="flex">
                        <span
                          data-testid="slug-host-prefix"
                          className="inline-flex items-center rounded-s-md border border-e-0 bg-muted px-3 text-sm text-muted-foreground"
                        >
                          {appHost}/
                        </span>
                        <Input
                          id="org-slug"
                          value={orgInfo.slug}
                          onChange={(e) =>
                            setOrgInfo((p) => ({
                              ...p,
                              slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''),
                            }))
                          }
                          className="rounded-s-none"
                          disabled={!canUpdateTenant || !owner}
                          aria-describedby="org-slug-help"
                        />
                      </div>
                      <p
                        id="org-slug-help"
                        className="flex items-start gap-1 text-xs text-muted-foreground"
                      >
                        {!owner && <Lock className="mt-0.5 size-3 shrink-0" aria-hidden />}
                        {owner
                          ? t(
                              'org.general.slugHelpOwner',
                              'Lowercase letters, numbers and hyphens. Changing it breaks saved links, and it cannot change while single sign-on is configured.'
                            )
                          : t('org.general.slugHelpLocked', 'Only the owner can change the URL.')}
                      </p>
                      <OrganizationRegion slug={currentTenant?.slug} />
                    </div>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="org-website">{t('org.general.website', 'Website')}</Label>
                      <Input
                        id="org-website"
                        type="url"
                        placeholder="https://example.com"
                        value={general.website}
                        onChange={(e) => setGeneral((g) => ({ ...g, website: e.target.value }))}
                        disabled={!canUpdateTenant}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {owner && (
            <div id="danger-zone">
              <DangerZone>
                <DangerZoneItem
                  title={t('org.danger.transferTitle', 'Transfer ownership')}
                  description={t(
                    'org.danger.transferDesc',
                    'Make another member the owner. You choose your new role; the new owner must accept. Open the member in Members and choose Transfer ownership.'
                  )}
                  action={
                    <Button variant="outline" size="sm" asChild>
                      <Link href="/settings/members">
                        <UserCog className="h-4 w-4" aria-hidden />
                        {t('org.danger.transferAction', 'Choose the new owner')}
                      </Link>
                    </Button>
                  }
                />
                <DeleteOrganizationItem />
              </DangerZone>
            </div>
          )}

          <SettingsSaveBar
            dirty={dirty}
            saving={saving}
            onSave={() => void handleSave()}
            onDiscard={reset}
          />
        </TabsContent>

        <TabsContent value="storage" className="mt-5 space-y-5">
          <StorageConfigCard />
        </TabsContent>
      </Tabs>
    </Main>
  )
}
