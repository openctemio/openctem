'use client'

import { useEffect, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { Trash2, Copy, Check, Loader2, RotateCcw } from 'lucide-react'
import { ErrorState } from '@/features/shared'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { copyToClipboard } from '@/lib/clipboard'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  useSamlConfig,
  useSaveSamlConfig,
  useDeleteSamlConfig,
  usePendingSSOChanges,
} from '@console/features/saml/api/use-saml-config'
import {
  isPendingSSOChange,
  PENDING_SSO_MESSAGE,
} from '@/features/sso-approvals/api/use-sso-changes'
import { emptySamlConfig, type SamlConfig } from '@console/features/saml/types/saml.types'
import { useTranslation } from '@/context/i18n-provider'

function CopyableUrl({ label, url }: { label: string; url: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-1">
      <Label className="text-muted-foreground text-xs">{label}</Label>
      <div className="flex items-center gap-2">
        <code className="bg-muted min-w-0 flex-1 truncate rounded px-2 py-1 text-xs">{url}</code>
        <Button
          type="button"
          size="icon"
          variant="ghost"
          onClick={async () => {
            await copyToClipboard(url)
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </Button>
      </div>
    </div>
  )
}

interface SamlConfigFormProps {
  /** Organization being configured. */
  tenantId: string
  /** Organization slug; the SP URLs are built from it. */
  tenantSlug: string
  /** False for a read-only administrator: the form is shown disabled. */
  canManage: boolean
  /** Called after a save or removal, e.g. to refresh the organization summary. */
  onChanged?: () => void
}

/**
 * SAML 2.0 service-provider configuration for one organization. Used by the
 * platform admin console (RFC-022); SSO setup is not a tenant operation.
 */
export function SamlConfigForm({
  tenantId,
  tenantSlug,
  canManage,
  onChanged,
}: SamlConfigFormProps) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useSamlConfig(tenantId)
  const { trigger: save, isMutating: isSaving } = useSaveSamlConfig(tenantId)
  const { trigger: remove, isMutating: isDeleting } = useDeleteSamlConfig(tenantId)
  const { mutate: mutatePending } = usePendingSSOChanges(tenantId)

  const [form, setForm] = useState<SamlConfig>(emptySamlConfig)
  const [domainsText, setDomainsText] = useState('')
  const [removeOpen, setRemoveOpen] = useState(false)

  const resetToSaved = () => {
    setForm(data ?? emptySamlConfig)
    setDomainsText((data?.allowed_domains ?? []).join(', '))
  }

  useEffect(() => {
    if (data) {
      setForm(data)
      setDomainsText((data.allowed_domains ?? []).join(', '))
    }
  }, [data])

  // Save is enabled only once something differs from what the server holds.
  const isDirty =
    JSON.stringify({ ...form, allowed_domains: undefined }) !==
      JSON.stringify({ ...(data ?? emptySamlConfig), allowed_domains: undefined }) ||
    domainsText !== (data?.allowed_domains ?? []).join(', ')

  const spURLs = useMemo(() => {
    const slug = tenantSlug
    if (!slug || typeof window === 'undefined') return null
    const base = `${window.location.origin}/api/v1/auth/saml/${slug}`
    return {
      metadata: `${base}/metadata`,
      acs: `${base}/acs`,
      login: `${base}/login`,
    }
  }, [tenantSlug])

  const set = <K extends keyof SamlConfig>(key: K, value: SamlConfig[K]) =>
    setForm((f) => ({ ...f, [key]: value }))

  const handleSave = async () => {
    const payload: SamlConfig = {
      ...form,
      allowed_domains: domainsText
        .split(',')
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean),
    }
    try {
      const res = await save(payload)
      if (isPendingSSOChange(res)) {
        // Stored for an owner's approval; the live config is unchanged.
        toast.info(t('admin.identityProvidersPanel.pendingChange', PENDING_SSO_MESSAGE))
        resetToSaved()
        void mutatePending()
      } else {
        toast.success(t('admin.samlConfigForm.samlConfigurationSaved', 'SAML configuration saved'))
        void mutate()
      }
      onChanged?.()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t(
            'admin.samlConfigForm.failedToSaveSamlConfiguration',
            'Failed to save SAML configuration'
          )
        )
      )
    }
  }

  const handleDelete = async () => {
    try {
      await remove()
      toast.success(
        t('admin.samlConfigForm.samlConfigurationRemoved', 'SAML configuration removed')
      )
      setRemoveOpen(false)
      setForm(emptySamlConfig)
      setDomainsText('')
      void mutate()
      onChanged?.()
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t(
            'admin.samlConfigForm.failedToRemoveSamlConfiguration',
            'Failed to remove SAML configuration'
          )
        )
      )
    }
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-end gap-2">
        {canManage && !error && !isLoading && (
          <>
            {data && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRemoveOpen(true)}
                disabled={isDeleting}
              >
                <Trash2 className="me-2 h-4 w-4" />
                {t('admin.samlConfigForm.remove', 'Remove')}
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={resetToSaved} disabled={!isDirty}>
              <RotateCcw className="me-2 h-4 w-4" />
              {t('admin.samlConfigForm.reset', 'Reset')}
            </Button>
            <Button size="sm" onClick={handleSave} disabled={!isDirty || isSaving}>
              {isSaving && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              {t('admin.samlConfigForm.saveChanges', 'Save changes')}
            </Button>
          </>
        )}
      </div>

      <div className="mt-4">
        {error ? (
          // A read failure must NOT fall through to the blank form: it reads as
          // "SAML is not configured", and saving from there would PUT empty values
          // over a live IdP config the admin never saw.
          <ErrorState
            title={t('admin.samlConfigForm.samlConfiguration', 'SAML configuration')}
            error={error}
            onRetry={() => void mutate()}
          />
        ) : isLoading ? (
          <div className="space-y-3">
            <Skeleton className="h-32 w-full" />
            <Skeleton className="h-64 w-full" />
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
            <div className="space-y-5 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>
                    {t('admin.samlConfigForm.identityProvider', 'Identity provider')}
                  </CardTitle>
                  <CardDescription>
                    {t(
                      'admin.samlConfigForm.pasteTheDetailsFromYour',
                      "Paste the details from your IdP's SAML application. Login stays disabled until you enable it below."
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="idp_entity_id">
                      {t('admin.samlConfigForm.idpEntityIdIssuer', 'IdP entity ID (issuer)')}
                    </Label>
                    <Input
                      id="idp_entity_id"
                      value={form.idp_entity_id}
                      disabled={!canManage}
                      onChange={(e) => set('idp_entity_id', e.target.value)}
                      placeholder="https://idp.example.com/saml/metadata"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="idp_sso_url">
                      {t('admin.samlConfigForm.idpSsoUrl', 'IdP SSO URL')}
                    </Label>
                    <Input
                      id="idp_sso_url"
                      value={form.idp_sso_url}
                      disabled={!canManage}
                      onChange={(e) => set('idp_sso_url', e.target.value)}
                      placeholder="https://idp.example.com/sso/saml"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="idp_certificate">
                      {t(
                        'admin.samlConfigForm.idpSigningCertificatePem',
                        'IdP signing certificate (PEM)'
                      )}
                    </Label>
                    <Textarea
                      id="idp_certificate"
                      value={form.idp_certificate}
                      disabled={!canManage}
                      onChange={(e) => set('idp_certificate', e.target.value)}
                      placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                      className="min-h-[140px] font-mono text-xs"
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('admin.samlConfigForm.provisioning', 'Provisioning')}</CardTitle>
                  <CardDescription>
                    {t(
                      'admin.samlConfigForm.howUsersAreMappedWhen',
                      'How users are mapped when they log in via SAML.'
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="allowed_domains">
                      {t('admin.samlConfigForm.allowedEmailDomains', 'Allowed email domains')}
                    </Label>
                    <Input
                      id="allowed_domains"
                      value={domainsText}
                      disabled={!canManage}
                      onChange={(e) => setDomainsText(e.target.value)}
                      placeholder={t(
                        'admin.samlConfigForm.acmeComContosoComBlank',
                        'acme.com, contoso.com (blank = any)'
                      )}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>
                      {t(
                        'admin.samlConfigForm.defaultRoleForNewUsers',
                        'Default role for new users'
                      )}
                    </Label>
                    <Select
                      value={form.default_role}
                      disabled={!canManage}
                      onValueChange={(v) => set('default_role', v)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="member">
                          {t('admin.samlConfigForm.member', 'Member')}
                        </SelectItem>
                        <SelectItem value="viewer">
                          {t('admin.samlConfigForm.viewer', 'Viewer')}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-center justify-between rounded-md border p-3">
                    <div>
                      <p className="text-sm font-medium">
                        {t('admin.samlConfigForm.autoProvisionUsers', 'Auto-provision users')}
                      </p>
                      <p className="text-muted-foreground text-xs">
                        {t(
                          'admin.samlConfigForm.createAnAccountOnFirst',
                          'Create an account on first login for allowed domains.'
                        )}
                      </p>
                    </div>
                    <Switch
                      aria-label={t(
                        'admin.samlConfigForm.autoProvisionUsers',
                        'Auto-provision users'
                      )}
                      checked={form.auto_provision}
                      disabled={!canManage}
                      onCheckedChange={(v) => set('auto_provision', v)}
                    />
                  </div>
                  <div className="flex items-center justify-between rounded-md border p-3">
                    <div>
                      <p className="text-sm font-medium">
                        {t('admin.samlConfigForm.enableSamlLogin', 'Enable SAML login')}
                      </p>
                      <p className="text-muted-foreground text-xs">
                        {t(
                          'admin.samlConfigForm.whenOffSamlIsConfigured',
                          'When off, SAML is configured but the login endpoint refuses requests.'
                        )}
                      </p>
                    </div>
                    <Switch
                      aria-label={t('admin.samlConfigForm.enableSamlLogin', 'Enable SAML login')}
                      checked={form.enabled}
                      disabled={!canManage}
                      onCheckedChange={(v) => set('enabled', v)}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="space-y-5">
              <Card>
                <CardHeader>
                  <CardTitle>
                    {t('admin.samlConfigForm.serviceProviderDetails', 'Service provider details')}
                  </CardTitle>
                  <CardDescription>
                    {t(
                      'admin.samlConfigForm.registerTheseUrlsInYour',
                      "Register these URLs in your IdP's SAML application."
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {spURLs ? (
                    <>
                      <CopyableUrl
                        label={t('admin.samlConfigForm.metadataEntityId', 'Metadata / Entity ID')}
                        url={spURLs.metadata}
                      />
                      <CopyableUrl
                        label={t('admin.samlConfigForm.acsReplyUrl', 'ACS (reply) URL')}
                        url={spURLs.acs}
                      />
                      <Separator />
                      <CopyableUrl
                        label={t(
                          'admin.samlConfigForm.loginUrlSpInitiated',
                          'Login URL (SP-initiated)'
                        )}
                        url={spURLs.login}
                      />
                    </>
                  ) : (
                    <p className="text-muted-foreground text-sm">
                      {t(
                        'admin.samlConfigForm.serviceProviderUrlsAppearOnce',
                        'Service provider URLs appear once a tenant is selected.'
                      )}
                    </p>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </div>

      <ConfirmDialog
        open={removeOpen}
        onOpenChange={setRemoveOpen}
        title={t('confirm.saml.removeTitle', 'Remove the SAML configuration?')}
        desc={t(
          'confirm.saml.removeDesc',
          'People can no longer sign in through your identity provider. Make sure they have another way to sign in first. This cannot be undone.'
        )}
        confirmText={t('confirm.remove', 'Remove')}
        destructive
        isLoading={isDeleting}
        handleConfirm={() => void handleDelete()}
      />
    </div>
  )
}
