'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Trash2, Upload } from 'lucide-react'
import { toast } from 'sonner'
import {
  DangerZone,
  DangerZoneItem,
  SettingsBlock,
  SettingsField,
  SettingsFieldGrid,
  SettingsPage,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
} from '@/features/shared'
import { TextLink } from '@/components/ui/text-link'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
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
import { TimezoneSelect } from '@/features/scans/components/timezone-select'
import { DashboardDataCard } from './dashboard-data-card'
import { DeleteOrganizationItem } from './delete-organization'
import {
  StorageConfigSection,
  type StorageConfigHandle,
  type StorageFormState,
} from './storage-config-card'

/** The old in-page tabs (`?tab=`), now sections of the one page: the link still lands on its part. */
const TAB_SECTION: Record<string, string> = {
  storage: 'storage',
  'dashboard-data': 'dashboard-data',
}

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
 * Organization › General: one page of sections. The organization's name, URL,
 * logo, website and time zone; where files are stored; the dashboard data
 * state; and the owner's danger zone (transfer ownership, delete). One save
 * bar saves the organization form and the file storage form together.
 * Leaving an organization is in My account › Profile, where every member can
 * reach it.
 */
export function GeneralSettings() {
  const { t } = useTranslation()
  const appHost = useAppHost()
  const [tabParam] = useUrlFilter('tab', 'general')

  const { currentTenant, updateCurrentTenant, refreshTenants } = useTenant()
  const tenantId = currentTenant?.id
  const { isOwner } = usePermissions()
  // Owners and administrators only (the API's gate on the status and rebuild routes).
  const canSeeDashboardData = useCanMutate('POST /api/v1/dashboard-data/rebuild')
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
      primary_color: settings?.branding.primary_color || '#3B82F6', // design-ok: the stored brand colour default the API expects, not a UI colour
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

  // The file storage section keeps its own form; the page's bar saves it.
  const storageRef = useRef<StorageConfigHandle>(null)
  const [storage, setStorage] = useState<StorageFormState>({
    dirty: false,
    invalid: false,
    saving: false,
  })
  const [saveError, setSaveError] = useState(false)

  const restoreSaved = useCallback(() => {
    setOrgInfo({ name: currentTenant?.name || '', slug: currentTenant?.slug || '' })
    setGeneral(savedGeneral)
    setLogoDraft(undefined)
  }, [currentTenant?.name, currentTenant?.slug, savedGeneral])

  // Load the saved values into the form (and again after every save).
  useEffect(() => {
    restoreSaved()
  }, [restoreSaved])

  const discard = () => {
    restoreSaved()
    storageRef.current?.discard()
    setSaveError(false)
  }

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
  const dirty = planHasChanges(plan) || storage.dirty
  const saving = savingTenant || savingGeneral || savingBranding || storage.saving

  // What the bar counts and lists: one name per changed setting.
  const changes = useMemo(() => {
    const out: string[] = []
    if (plan.orgChanges?.name !== undefined) out.push(t('org.general.name', 'Organization name'))
    if (plan.orgChanges?.slug !== undefined) out.push(t('org.general.slug', 'URL slug'))
    if (plan.general) {
      if (general.website !== savedGeneral.website) out.push(t('org.general.website', 'Website'))
      if (general.timezone !== savedGeneral.timezone)
        out.push(t('org.general.timezone', 'Time zone'))
    }
    if (plan.branding) out.push(t('org.general.logo', 'Logo'))
    if (storage.dirty) out.push(t('org.general.tab.storage', 'File storage'))
    return out
  }, [plan, general, savedGeneral, storage.dirty, t])

  const saveOrg = async (): Promise<boolean> => {
    if (!planHasChanges(plan)) return true
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
      return true
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('org.general.saveFailed', 'Could not save the organization settings')
        )
      )
      return false
    }
  }

  // Each part saves on its own and keeps its changes when it fails.
  const handleSave = async () => {
    setSaveError(false)
    const orgOk = await saveOrg()
    const storageOk = (await storageRef.current?.save()) ?? true
    if (!orgOk || !storageOk) setSaveError(true)
  }

  // ?tab=storage and ?tab=dashboard-data were tabs of this page: land on the section.
  const ready = !isLoading && !isError
  const section = TAB_SECTION[tabParam]
  useEffect(() => {
    if (!ready || !section) return
    document.getElementById(section)?.scrollIntoView({ block: 'start' })
  }, [ready, section])

  const title = t('org.general.title', 'General')
  const description = t(
    'org.general.desc',
    "Your organization's name, logo and file storage, and the owner's danger zone."
  )
  if (!ready) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={isLoading ? 'loading' : 'error'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  const logoPreview =
    logoDraft === null ? undefined : safeImageSrc(logoDraft ?? (branding.logo_data || logoSrc))
  const hasLogo = logoDraft === undefined && Boolean(logoSrc || currentTenant?.logo_url)
  const savedName = currentTenant?.name || ''

  return (
    <SettingsPage title={title} description={description} readOnly={!canUpdateTenant}>
      <SettingsSection
        framed
        id="org-profile"
        title={t('org.general.profile', 'Organization information')}
        description={t('org.general.profileDesc', 'How your organization is named and recognised.')}
      >
        <SettingsRow
          stacked
          label={t('org.general.logo', 'Logo')}
          hint={
            <>
              {t('org.general.logoHint', 'PNG, JPEG or WebP, shown at up to 200 × 200 px')}
              {'. '}
              {!canUpdateTenant
                ? t('org.general.logoLocked', 'Only administrators can change the logo.')
                : logoDraft === null
                  ? t('org.general.logoWillRemove', 'The logo is removed when you save.')
                  : logoDraft !== undefined
                    ? t('org.general.logoWillReplace', 'The new logo is used when you save.')
                    : null}
            </>
          }
        >
          <Avatar className="size-10 rounded-md">
            <AvatarImage src={logoPreview} alt="" />
            <AvatarFallback className="rounded-md text-cap-m">
              {currentTenant?.name?.charAt(0) || 'O'}
            </AvatarFallback>
          </Avatar>
          {canUpdateTenant && (
            <>
              <Button variant="outline" asChild>
                <label className="cursor-pointer has-[:focus-visible]:ring-[3px] has-[:focus-visible]:ring-ring/50">
                  <Upload aria-hidden />
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
                        toast.error(t('org.general.logoUnreadable', 'That image could not be read'))
                      }
                    }}
                  />
                </label>
              </Button>
              {hasLogo && (
                <Button variant="outline" onClick={() => setLogoDraft(null)}>
                  <Trash2 aria-hidden />
                  {t('org.general.logoRemove', 'Remove logo')}
                </Button>
              )}
            </>
          )}
        </SettingsRow>

        <SettingsBlock>
          <SettingsFieldGrid>
            <SettingsField
              id="org-name"
              label={t('org.general.name', 'Organization name')}
              hint={
                orgInfo.name !== savedName && savedName
                  ? t('org.general.was', 'Was "{value}".', { value: savedName })
                  : undefined
              }
            >
              {(control) => (
                <Input
                  {...control}
                  value={orgInfo.name}
                  onChange={(e) => setOrgInfo((p) => ({ ...p, name: e.target.value }))}
                  disabled={!canUpdateTenant}
                  maxLength={100}
                />
              )}
            </SettingsField>
            <SettingsField id="org-website" label={t('org.general.website', 'Website')}>
              {(control) => (
                <Input
                  {...control}
                  type="url"
                  placeholder="https://example.com"
                  value={general.website}
                  onChange={(e) => setGeneral((g) => ({ ...g, website: e.target.value }))}
                  disabled={!canUpdateTenant}
                />
              )}
            </SettingsField>
            <SettingsField
              id="org-slug"
              label={t('org.general.slug', 'URL slug')}
              lock={owner ? undefined : t('org.general.ownerOnly', 'Owner only')}
              hint={
                owner
                  ? t(
                      'org.general.slugHelpOwner',
                      'Lowercase letters, numbers and hyphens. Changing it breaks saved links, and it cannot change while single sign-on is configured.'
                    )
                  : t('org.general.slugHelpLocked', 'Only the owner can change the URL.')
              }
            >
              {(control) => (
                <div className="flex min-w-0">
                  <span
                    data-testid="slug-host-prefix"
                    className="inline-flex max-w-[50%] min-w-0 items-center truncate rounded-s-md border border-e-0 bg-muted px-3 text-code text-muted-foreground"
                  >
                    {appHost}/
                  </span>
                  <Input
                    {...control}
                    value={orgInfo.slug}
                    onChange={(e) =>
                      setOrgInfo((p) => ({
                        ...p,
                        slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''),
                      }))
                    }
                    className="rounded-s-none"
                    disabled={!canUpdateTenant || !owner}
                  />
                </div>
              )}
            </SettingsField>
            <div id="org-timezone-setting" className="min-w-0">
              <SettingsField
                id="org-timezone"
                label={t('org.general.timezone', 'Time zone')}
                hint={t(
                  'org.general.timezoneHelp',
                  'The organization clock: alert quiet hours, the daily digest and scan approval hours use it.'
                )}
              >
                {(control) => (
                  <TimezoneSelect
                    id={control.id}
                    aria-describedby={control['aria-describedby']}
                    value={general.timezone}
                    onChange={(zone) => setGeneral((g) => ({ ...g, timezone: zone }))}
                    disabled={!canUpdateTenant}
                  />
                )}
              </SettingsField>
            </div>
          </SettingsFieldGrid>
          <OrganizationRegion slug={currentTenant?.slug} />
        </SettingsBlock>
      </SettingsSection>

      <StorageConfigSection ref={storageRef} onStateChange={setStorage} />

      {canSeeDashboardData && <DashboardDataCard />}

      {owner && (
        <DangerZone
          id="danger-zone"
          description={t('org.danger.ownerOnly', 'Shown to the owner only.')}
        >
          <DangerZoneItem
            title={t('org.danger.transferTitle', 'Transfer ownership')}
            description={t(
              'org.danger.transferDesc',
              'Make another member the owner. You choose your new role; the new owner must accept. Open the member in Members and choose Transfer ownership.'
            )}
            action={
              <TextLink
                href="/settings/members"
                className="text-dense font-medium text-signal-text"
              >
                {t('org.danger.transferAction', 'Choose the new owner')}
              </TextLink>
            }
          />
          <DeleteOrganizationItem />
        </DangerZone>
      )}

      <SettingsSaveBar
        dirty={dirty}
        saving={saving}
        saveDisabled={storage.dirty && storage.invalid}
        changes={changes}
        error={
          saveError
            ? t('settings.saveBar.failed', "Couldn't save. Your changes are kept.")
            : undefined
        }
        onSave={() => void handleSave()}
        onDiscard={discard}
      />
    </SettingsPage>
  )
}
