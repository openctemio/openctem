'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useUrlFilter } from '@/hooks/use-url-param'
import { Main } from '@/components/layout'
import { PageHeader } from '@/features/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Save, Building, Upload, Loader2, AlertCircle, Lock } from 'lucide-react'
import { useCanMutate } from '@/lib/permissions'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { get, patch } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import {
  useTenantSettings,
  useUpdateTenant,
  useUpdateGeneralSettings,
  useUpdateSecuritySettings,
  useUpdateBrandingSettings,
} from '../api/use-tenant-settings'
import { useTenantLogo } from '../hooks/use-tenant-logo'
import { planGeneralSave, planHasChanges } from '../lib/general-save-plan'
import {} from '../types/settings.types'
import { AccessRestrictionsCard, isIpLockoutError, parseLines } from './access-restrictions-card'
import { DeleteOrganization } from './delete-organization'
import { SsoManagedNotice } from '@/features/sso/components/sso-managed-by-platform'
import { safeImageSrc } from '@/lib/safe-href'

const STORAGE_FORM_ID = 'storage-config-form'

interface StorageStatus {
  canSave: boolean
  saving: boolean
}

/**
 * The storage tab owns its own fields; it renders them as a <form> so the page
 * header's Save button (the one Save every settings page has) can submit it via
 * `form={STORAGE_FORM_ID}`, and reports whether saving is possible.
 */
function StorageConfigTab({ onStatusChange }: { onStatusChange: (s: StorageStatus) => void }) {
  const [provider, setProvider] = useState('local')
  const [bucket, setBucket] = useState('')
  const [region, setRegion] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [accessKey, setAccessKey] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [loaded, setLoaded] = useState(false)

  // Load current config via API client (includes CSRF + auth)
  useEffect(() => {
    get('/api/v1/attachments/storage-config')
      .then((data: unknown) => {
        const d = data as Record<string, unknown> | null
        if (!d) {
          setLoaded(true)
          return
        }
        if (d?.configured) {
          setProvider((d.provider as string) || 'local')
          setBucket((d.bucket as string) || '')
          setRegion((d.region as string) || '')
          setEndpoint((d.endpoint as string) || '')
        }
        setLoaded(true)
      })
      .catch(() => setLoaded(true))
  }, [])

  const handleSave = async (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      await patch('/api/v1/attachments/storage-config', {
        provider,
        bucket,
        region,
        endpoint,
        access_key: accessKey,
        secret_key: secretKey,
      })
      toast.success('Storage configuration saved')
      setAccessKey('')
      setSecretKey('')
    } catch {
      toast.error('Failed to save storage configuration')
    } finally {
      setSaving(false)
    }
  }

  const isCloud = provider === 's3' || provider === 'minio'
  const canSave = loaded && !saving && !(isCloud && !bucket)

  useEffect(() => {
    onStatusChange({ canSave, saving })
  }, [canSave, saving, onStatusChange])

  if (!loaded) return <Skeleton className="h-48 w-full rounded-xl" />

  return (
    <form id={STORAGE_FORM_ID} onSubmit={handleSave}>
      <Card>
        <CardHeader>
          <CardTitle>Storage provider</CardTitle>
          <CardDescription>
            Choose where uploaded evidence and attachments are stored
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Provider</Label>
            <Select value={provider} onValueChange={setProvider}>
              <SelectTrigger className="w-full sm:w-[280px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="local">
                  <span className="flex items-center gap-2">Local filesystem</span>
                </SelectItem>
                <SelectItem value="s3">Amazon S3</SelectItem>
                <SelectItem value="minio">MinIO (S3-compatible)</SelectItem>
              </SelectContent>
            </Select>
            {!isCloud && (
              <p className="text-sm text-muted-foreground">
                Files stored on the server disk at the default storage path.
              </p>
            )}
          </div>

          {isCloud && (
            <>
              <Separator />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Bucket name *</Label>
                  <Input
                    value={bucket}
                    onChange={(e) => setBucket(e.target.value)}
                    placeholder="my-pentest-evidence"
                  />
                </div>
                <div className="space-y-2">
                  <Label>Region</Label>
                  <Input
                    value={region}
                    onChange={(e) => setRegion(e.target.value)}
                    placeholder="ap-southeast-1"
                  />
                </div>
                {provider === 'minio' && (
                  <div className="space-y-2 sm:col-span-2">
                    <Label>Endpoint *</Label>
                    <Input
                      value={endpoint}
                      onChange={(e) => setEndpoint(e.target.value)}
                      placeholder="https://minio.internal:9000"
                    />
                  </div>
                )}
                <div className="space-y-2">
                  <Label>Access key</Label>
                  <Input
                    value={accessKey}
                    onChange={(e) => setAccessKey(e.target.value)}
                    placeholder="AKIA..."
                    type="password"
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave empty to keep existing credentials
                  </p>
                </div>
                <div className="space-y-2">
                  <Label>Secret key</Label>
                  <Input
                    value={secretKey}
                    onChange={(e) => setSecretKey(e.target.value)}
                    placeholder="••••••••"
                    type="password"
                  />
                </div>
              </div>
              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Existing files on local storage will remain accessible after switching. Each file
                  remembers which provider stores it.
                </AlertDescription>
              </Alert>
            </>
          )}
        </CardContent>
      </Card>
    </form>
  )
}

export type OrganizationSettingsView = 'general' | 'authentication'

const VIEW_HEADER: Record<OrganizationSettingsView, { title: string; description: string }> = {
  general: {
    title: 'General',
    description: "Your organization's name, branding, localization and file storage.",
  },
  authentication: {
    title: 'Authentication',
    description: 'How members sign in: two-factor, session length and sign-in restrictions.',
  },
}
const GENERAL_TABS = ['general', 'storage'] as const

/**
 * The active tab's one Save, in the page header like every settings page. A
 * permission-locked Save stays visible (disabled, with a lock and the reason)
 * so the admin knows why nothing can be changed.
 */
function HeaderSaveButton({
  onClick,
  form,
  busy,
  disabled = false,
  locked = false,
  lockedReason,
}: {
  onClick?: () => void
  form?: string
  busy: boolean
  disabled?: boolean
  locked?: boolean
  lockedReason?: string
}) {
  const button = (
    <Button
      size="sm"
      type={form ? 'submit' : 'button'}
      form={form}
      onClick={onClick}
      disabled={busy || disabled || locked}
    >
      {busy ? (
        <Loader2 className="h-4 w-4 animate-spin" />
      ) : locked ? (
        <Lock className="h-4 w-4" />
      ) : (
        <Save className="h-4 w-4" />
      )}
      Save changes
    </Button>
  )
  if (!locked || !lockedReason) return button
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span>{button}</span>
        </TooltipTrigger>
        <TooltipContent>
          <p>{lockedReason}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

/**
 * Organization settings, two pages over one settings load:
 * - /settings/general: organization info, branding, localization and file
 *   storage (tabs), and the owner-only danger zone;
 * - /settings/authentication: two-factor, session, e-mail verification,
 *   access restrictions, plus where SSO is configured.
 * Was /settings/tenant with four tabs; its API & Webhooks tab is gone: those
 * fields were stored and read back but nothing in the API acted on them.
 * Outbound webhooks live under Integrations > Notification channels.
 */
export function OrganizationSettings({ view }: { view: OrganizationSettingsView }) {
  const { title: PAGE_TITLE, description: PAGE_DESCRIPTION } = VIEW_HEADER[view]
  const [tabParam, setTabParam] = useUrlFilter('tab', 'general')
  const activeTab =
    view === 'authentication'
      ? 'security'
      : (GENERAL_TABS as readonly string[]).includes(tabParam)
        ? tabParam
        : 'general'
  const setActiveTab = (next: string) => setTabParam(next === 'general' ? '' : next)
  const [storageStatus, setStorageStatus] = useState<StorageStatus>({
    canSave: false,
    saving: false,
  })
  const onStorageStatus = useCallback((st: StorageStatus) => setStorageStatus(st), [])

  const { currentTenant, updateCurrentTenant, refreshTenants } = useTenant()
  const tenantId = currentTenant?.id

  // Controls follow the API route gates (permission + role), so a custom
  // role with team:update but not admin no longer sees a Save that 403s.
  const canUpdateTenant = useCanMutate(
    'PATCH /api/v1/tenants/{tenant}',
    'PATCH /api/v1/tenants/{tenant}/settings/general',
    'PATCH /api/v1/tenants/{tenant}/settings/branding'
  )
  // Security settings are owner-only on the backend (RequireTeamOwner).
  const canManageSecurityAndAPI = useCanMutate('PATCH /api/v1/tenants/{tenant}/settings/security')
  // Storage configuration is admin-only (RequireAdmin).
  const canSaveStorage = useCanMutate('PATCH /api/v1/attachments/storage-config')

  // Fetch settings
  const { settings, isLoading, isError, error, mutate } = useTenantSettings(tenantId)

  // Update hooks
  const { updateTenant, isUpdating: isUpdatingTenant } = useUpdateTenant(tenantId)
  const { updateGeneralSettings, isUpdating: isUpdatingGeneral } =
    useUpdateGeneralSettings(tenantId)
  const { updateSecuritySettings, isUpdating: isUpdatingSecurity } =
    useUpdateSecuritySettings(tenantId)
  const { updateBrandingSettings, isUpdating: isUpdatingBranding } =
    useUpdateBrandingSettings(tenantId)

  // Combined loading state (for potential future use in global loading indicator)
  const _isUpdating =
    isUpdatingTenant || isUpdatingGeneral || isUpdatingSecurity || isUpdatingBranding

  // Organization info form state (name, slug)
  const [orgInfoForm, setOrgInfoForm] = useState({
    name: '',
    slug: '',
  })
  const [_hasOrgInfoChanges, setHasOrgInfoChanges] = useState(false)

  // A logo picked or removed but not saved yet: undefined = unchanged,
  // a data URL = replace, null = remove. The header Save writes it.
  const [logoDraft, setLogoDraft] = useState<string | null | undefined>(undefined)

  // Cached logo hook
  const { logoSrc, updateLogo } = useTenantLogo(
    tenantId,
    settings?.branding.logo_data,
    currentTenant?.logo_url
  )

  // Local form state
  const [generalForm, setGeneralForm] = useState({
    timezone: 'UTC',
    language: 'en',
    industry: '',
    website: '',
  })

  // Inline error under the IP allowlist (the API's lockout refusal).
  const [ipAllowlistError, setIpAllowlistError] = useState<string | null>(null)
  const [securityForm, setSecurityForm] = useState({
    mfa_required: false,
    session_timeout_min: 60,
    ip_whitelist: '',
    allowed_domains: '',
    email_verification_mode: 'auto' as 'auto' | 'always' | 'never',
    require_sensor_local_policy_for_private_targets: false,
  })

  const [brandingForm, setBrandingForm] = useState({
    primary_color: '#3B82F6',
    logo_dark_url: '',
    logo_data: null as string | null,
  })

  // Populate org info form when tenant loads - syncing with external data

  useEffect(() => {
    if (currentTenant) {
      setOrgInfoForm({
        name: currentTenant.name || '',
        slug: currentTenant.slug || '',
      })
      setHasOrgInfoChanges(false)
    }
  }, [currentTenant])

  // Populate settings form when settings load - syncing with external data

  useEffect(() => {
    if (settings) {
      setGeneralForm({
        timezone: settings.general.timezone || 'UTC',
        language: settings.general.language || 'en',
        industry: settings.general.industry || '',
        website: settings.general.website || '',
      })
      setSecurityForm({
        mfa_required: settings.security.mfa_required || false,
        session_timeout_min: settings.security.session_timeout_min || 60,
        ip_whitelist: (settings.security.ip_whitelist || []).join('\n'),
        allowed_domains: (settings.security.allowed_domains || []).join('\n'),
        email_verification_mode:
          (settings.security.email_verification_mode as 'auto' | 'always' | 'never') || 'auto',
        require_sensor_local_policy_for_private_targets:
          settings.security.require_sensor_local_policy_for_private_targets || false,
      })
      setBrandingForm({
        primary_color: settings.branding.primary_color || '#3B82F6',
        logo_dark_url: settings.branding.logo_dark_url || '',
        logo_data: settings.branding.logo_data || null,
      })
    }
  }, [settings])

  // Handle org info changes
  const handleOrgInfoChange = (field: 'name' | 'slug', value: string) => {
    // Validate slug format (lowercase letters, numbers, hyphens)
    if (field === 'slug') {
      value = value.toLowerCase().replace(/[^a-z0-9-]/g, '')
    }
    setOrgInfoForm((prev) => ({ ...prev, [field]: value }))
    const hasChanges =
      (field === 'name' ? value : orgInfoForm.name) !== currentTenant?.name ||
      (field === 'slug' ? value : orgInfoForm.slug) !== currentTenant?.slug
    setHasOrgInfoChanges(hasChanges)
  }

  // Save org info (kept for potential standalone use)
  const _handleSaveOrgInfo = async () => {
    try {
      const changes: { name?: string; slug?: string } = {}
      if (orgInfoForm.name !== currentTenant?.name) {
        changes.name = orgInfoForm.name
      }
      if (orgInfoForm.slug !== currentTenant?.slug) {
        changes.slug = orgInfoForm.slug
      }
      if (Object.keys(changes).length === 0) {
        return
      }
      const result = await updateTenant(changes)
      if (result) {
        // Update tenant context without reload
        updateCurrentTenant(changes)
        refreshTenants()
        toast.success('Organization info updated successfully')
        setHasOrgInfoChanges(false)
      }
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to update organization info'))
    }
  }

  // Save handler for the General tab: org info, general settings and the logo
  // all go through this one Save (see lib/general-save-plan.ts).
  const handleSaveSettings = async () => {
    const plan = planGeneralSave({
      orgInfo: orgInfoForm,
      current: currentTenant,
      generalForm,
      savedGeneral: settings?.general,
      branding: brandingForm,
      logoDraft,
    })
    if (!planHasChanges(plan)) {
      toast.info('No changes to save')
      return
    }
    try {
      if (plan.orgChanges) {
        await updateTenant(plan.orgChanges)
        // Update tenant context without reload
        updateCurrentTenant(plan.orgChanges)
        // Refresh tenants list in background
        refreshTenants()
        setHasOrgInfoChanges(false)
      }
      if (plan.general) {
        const result = await updateGeneralSettings(plan.general)
        if (result) mutate(result)
      }
      if (plan.branding) {
        const result = await updateBrandingSettings(plan.branding)
        if (result) {
          mutate(result)
          updateLogo(plan.branding.logo_data)
          setBrandingForm(plan.branding)
          setLogoDraft(undefined)
        }
      }
      toast.success('Settings saved successfully')
    } catch (error) {
      toast.error(getErrorMessage(error, 'Failed to save settings'))
    }
  }

  // Keep old handler for backwards compatibility
  const handleSaveGeneral = handleSaveSettings

  const handleSaveSecurity = async () => {
    setIpAllowlistError(null)
    try {
      const ipWhitelist = parseLines(securityForm.ip_whitelist)
      const allowedDomains = parseLines(securityForm.allowed_domains)

      const result = await updateSecuritySettings({
        mfa_required: securityForm.mfa_required,
        ip_whitelist: ipWhitelist,
        allowed_domains: allowedDomains,
        email_verification_mode: securityForm.email_verification_mode,
        require_sensor_local_policy_for_private_targets:
          securityForm.require_sensor_local_policy_for_private_targets,
      })
      if (result) {
        mutate(result)
        toast.success('Security settings saved successfully')
      }
    } catch (error) {
      // The API refuses an allowlist that would lock the caller out; show that
      // next to the field, not only in a toast.
      if (isIpLockoutError(error)) {
        setIpAllowlistError(error.message)
      }
      toast.error(getErrorMessage(error, 'Failed to save security settings'))
    }
  }

  // Loading state
  if (isLoading) {
    return (
      <>
        <Main>
          <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION} />
          <div className="mt-5 space-y-5">
            <Skeleton className="h-9 w-96 max-w-full" />
            <Skeleton className="h-64 w-full rounded-xl" />
            <Skeleton className="h-64 w-full rounded-xl" />
          </div>
        </Main>
      </>
    )
  }

  // Error state
  if (isError) {
    return (
      <>
        <Main>
          <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION} />
          <Alert variant="destructive" className="mt-5">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Failed to load settings</AlertTitle>
            <AlertDescription>
              <p>{error?.message || 'Unknown error'}</p>
              <Button variant="outline" size="sm" className="mt-2" onClick={() => void mutate()}>
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        </Main>
      </>
    )
  }

  return (
    <>
      <Main>
        <PageHeader title={PAGE_TITLE} description={PAGE_DESCRIPTION}>
          {activeTab === 'general' && (
            <HeaderSaveButton
              onClick={handleSaveGeneral}
              busy={isUpdatingTenant || isUpdatingGeneral || isUpdatingBranding}
              locked={!canUpdateTenant}
              lockedReason="You do not have permission to update organization settings"
            />
          )}
          {activeTab === 'security' && (
            <HeaderSaveButton
              onClick={handleSaveSecurity}
              busy={isUpdatingSecurity}
              locked={!canManageSecurityAndAPI}
              lockedReason="Only the organization owner can change these settings"
            />
          )}
          {activeTab === 'storage' && (
            <HeaderSaveButton
              form={STORAGE_FORM_ID}
              busy={storageStatus.saving}
              disabled={!storageStatus.canSave}
              locked={!canSaveStorage}
              lockedReason="Only administrators can change the file storage"
            />
          )}
        </PageHeader>

        {view === 'authentication' ? (
          <div className="mt-5 space-y-5">
            <Card>
              <CardHeader>
                <CardTitle>Sign-in</CardTitle>
                <CardDescription>
                  Two-factor, session length and e-mail verification
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="tenant-mfa-required">Require two-factor authentication</Label>
                    <p className="text-sm text-muted-foreground" id="tenant-mfa-required-desc">
                      Members who sign in with a password must set up an authenticator app at their
                      next sign-in. Members who sign in through SSO use your identity
                      provider&apos;s two-factor settings.
                    </p>
                  </div>
                  <Switch
                    id="tenant-mfa-required"
                    aria-describedby="tenant-mfa-required-desc"
                    checked={securityForm.mfa_required}
                    onCheckedChange={(checked) =>
                      setSecurityForm({ ...securityForm, mfa_required: checked })
                    }
                    disabled={!canManageSecurityAndAPI}
                  />
                </div>

                <Separator />

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="tenant-private-targets-local-policy">
                      Private targets need a sensor-local policy
                    </Label>
                    <p
                      className="text-sm text-muted-foreground"
                      id="tenant-private-targets-local-policy-desc"
                    >
                      Jobs that scan private addresses (RFC 1918, internal domains) go only to
                      sensors whose network owner installed a local policy. Other sensors leave them
                      for one that has it.
                    </p>
                  </div>
                  <Switch
                    id="tenant-private-targets-local-policy"
                    aria-describedby="tenant-private-targets-local-policy-desc"
                    checked={securityForm.require_sensor_local_policy_for_private_targets}
                    onCheckedChange={(checked) =>
                      setSecurityForm({
                        ...securityForm,
                        require_sensor_local_policy_for_private_targets: checked,
                      })
                    }
                    disabled={!canManageSecurityAndAPI}
                  />
                </div>

                <Separator />

                {/* Session timeout is hidden until per-organization session policy is
                    enforced (owner decision B5); the stored value is not sent. */}

                <div className="space-y-2">
                  <Label>Email verification</Label>
                  <p className="text-sm text-muted-foreground">
                    Controls whether new users must verify their email address before login.
                  </p>
                  <Select
                    value={securityForm.email_verification_mode}
                    onValueChange={(value) =>
                      setSecurityForm({
                        ...securityForm,
                        email_verification_mode: value as 'auto' | 'always' | 'never',
                      })
                    }
                    disabled={!canManageSecurityAndAPI}
                  >
                    <SelectTrigger className="w-full max-w-md">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">
                        <div className="flex flex-col items-start">
                          <span className="font-medium">Auto (Recommended)</span>
                          <span className="text-xs text-muted-foreground">
                            Require verification only when SMTP is configured
                          </span>
                        </div>
                      </SelectItem>
                      <SelectItem value="always">
                        <div className="flex flex-col items-start">
                          <span className="font-medium">Always require</span>
                          <span className="text-xs text-muted-foreground">
                            Force verification (SMTP must be configured to deliver emails)
                          </span>
                        </div>
                      </SelectItem>
                      <SelectItem value="never">
                        <div className="flex flex-col items-start">
                          <span className="font-medium">Never require</span>
                          <span className="text-xs text-muted-foreground">
                            Skip verification — users marked verified on registration. Use only for
                            closed/internal deployments.
                          </span>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                  {securityForm.email_verification_mode === 'never' && (
                    <p className="mt-2 flex items-start gap-2 text-sm text-destructive">
                      <AlertCircle className="h-4 w-4 mt-0.5 shrink-0" />
                      <span>
                        Warning: anyone can register with any email address. This opens the door to
                        account hijacking via email spoofing. Only use on internal deployments where
                        registration is restricted by other means.
                      </span>
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Allowed email domains + IP allowlist (both enforced by the API) */}
            <AccessRestrictionsCard
              ipAllowlist={securityForm.ip_whitelist}
              allowedDomains={securityForm.allowed_domains}
              onIpAllowlistChange={(value) => {
                setIpAllowlistError(null)
                setSecurityForm({ ...securityForm, ip_whitelist: value })
              }}
              onAllowedDomainsChange={(value) =>
                setSecurityForm({ ...securityForm, allowed_domains: value })
              }
              currentIp={settings?.security?.current_ip}
              ipAllowlistError={ipAllowlistError}
              disabled={!canManageSecurityAndAPI}
            />
            <SsoManagedNotice />
          </div>
        ) : (
          <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-4">
            <TabsList className="overflow-x-auto">
              <TabsTrigger value="general">
                <Building className="me-2 h-4 w-4" />
                General
              </TabsTrigger>
              <TabsTrigger value="storage">
                <Upload className="me-2 h-4 w-4" />
                File storage
              </TabsTrigger>
            </TabsList>

            {/* General Tab */}
            <TabsContent value="general" className="mt-5 space-y-5">
              <Card>
                <CardHeader>
                  <CardTitle>Organization information</CardTitle>
                  <CardDescription>Basic information about your organization</CardDescription>
                </CardHeader>
                <CardContent>
                  {/* 2-Column Layout: Logo | Details */}
                  <div className="flex flex-col lg:flex-row gap-8">
                    {/* Left Column - Logo */}
                    <div className="flex flex-col items-center lg:items-start gap-3 lg:border-r lg:pe-8">
                      {/* Logo with Hover Upload */}
                      <div className="relative group">
                        <Avatar className="h-24 w-24 ring-2 ring-border">
                          <AvatarImage
                            src={
                              logoDraft === null
                                ? undefined
                                : safeImageSrc(logoDraft ?? (brandingForm.logo_data || logoSrc))
                            }
                          />
                          <AvatarFallback className="text-3xl bg-primary/10">
                            {currentTenant?.name?.charAt(0) || 'T'}
                          </AvatarFallback>
                        </Avatar>
                        {canUpdateTenant ? (
                          <label className="absolute inset-0 flex items-center justify-center bg-black/60 rounded-full opacity-0 group-hover:opacity-100 cursor-pointer transition-opacity">
                            <Upload className="h-6 w-6 text-white" />
                            <input
                              type="file"
                              accept="image/png,image/jpeg,image/jpg,image/webp"
                              className="hidden"
                              onChange={async (e) => {
                                const file = e.target.files?.[0]
                                if (!file) return
                                const img = new Image()
                                const canvas = document.createElement('canvas')
                                const reader = new FileReader()
                                reader.onload = (ev) => {
                                  img.onload = () => {
                                    const maxSize = 200
                                    let w = img.width,
                                      h = img.height
                                    if (w > maxSize) {
                                      h = (h * maxSize) / w
                                      w = maxSize
                                    }
                                    if (h > maxSize) {
                                      w = (w * maxSize) / h
                                      h = maxSize
                                    }
                                    canvas.width = w
                                    canvas.height = h
                                    const ctx = canvas.getContext('2d')
                                    ctx?.drawImage(img, 0, 0, w, h)
                                    const dataUrl = canvas.toDataURL('image/jpeg', 0.85)
                                    setLogoDraft(dataUrl)
                                  }
                                  img.src = ev.target?.result as string
                                }
                                reader.readAsDataURL(file)
                                e.target.value = ''
                              }}
                            />
                          </label>
                        ) : (
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div className="absolute inset-0 flex items-center justify-center bg-black/40 rounded-full opacity-0 group-hover:opacity-100 cursor-not-allowed transition-opacity">
                                  <Lock className="h-6 w-6 text-white" />
                                </div>
                              </TooltipTrigger>
                              <TooltipContent>
                                <p>You do not have permission to update logo</p>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        )}
                      </div>

                      {/* Logo Actions */}
                      <div className="flex flex-col items-center gap-2">
                        {logoDraft !== undefined ? (
                          <>
                            <span className="rounded bg-muted px-2 py-1 text-xs text-muted-foreground">
                              {logoDraft === null ? 'Logo will be removed' : 'New logo'}: unsaved,
                              use Save changes
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setLogoDraft(undefined)}
                            >
                              Discard
                            </Button>
                          </>
                        ) : (
                          <>
                            <p className="text-xs text-muted-foreground text-center">
                              {canUpdateTenant ? (
                                <>
                                  Hover to upload
                                  <br />
                                  Max 200x200px
                                </>
                              ) : (
                                <>
                                  Logo upload disabled
                                  <br />
                                  Insufficient permissions
                                </>
                              )}
                            </p>
                            {(logoSrc || currentTenant?.logo_url) && canUpdateTenant && (
                              <Button
                                variant="ghost"
                                size="sm"
                                className="h-7 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
                                onClick={() => setLogoDraft(null)}
                              >
                                Remove
                              </Button>
                            )}
                          </>
                        )}
                      </div>
                    </div>

                    {/* Right Column - Organization Details */}
                    <div className="flex-1 space-y-4">
                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="name">Organization name</Label>
                          <Input
                            id="name"
                            value={orgInfoForm.name}
                            onChange={(e) => handleOrgInfoChange('name', e.target.value)}
                            placeholder="My Organization"
                            disabled={!canUpdateTenant}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="slug">URL slug</Label>
                          <div className="flex">
                            <span className="inline-flex items-center px-3 text-sm text-muted-foreground bg-muted border border-r-0 rounded-l-md">
                              app.openctem.io/
                            </span>
                            <Input
                              id="slug"
                              value={orgInfoForm.slug}
                              onChange={(e) => handleOrgInfoChange('slug', e.target.value)}
                              className="rounded-l-none"
                              placeholder="my-org"
                              disabled={!canUpdateTenant}
                            />
                          </div>
                          <p className="text-xs text-muted-foreground">
                            Lowercase letters, numbers, and hyphens only
                          </p>
                        </div>
                      </div>

                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label htmlFor="website">Website</Label>
                          <Input
                            id="website"
                            type="url"
                            placeholder="https://example.com"
                            value={generalForm.website}
                            onChange={(e) =>
                              setGeneralForm({ ...generalForm, website: e.target.value })
                            }
                            disabled={!canUpdateTenant}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Owner only; renders nothing for anyone else. */}
              <DeleteOrganization />
            </TabsContent>

            {/* Storage Tab */}
            <TabsContent value="storage" className="mt-5 space-y-5">
              <StorageConfigTab onStatusChange={onStorageStatus} />
            </TabsContent>
          </Tabs>
        )}
      </Main>
    </>
  )
}
