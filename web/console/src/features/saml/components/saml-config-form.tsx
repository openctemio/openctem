'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'
import { Trash2, Loader2, RotateCcw, Download, Upload } from 'lucide-react'
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
import { CopyableUrl } from '@console/features/sso/components/copyable-url'
import { useOrgIdentityProviders } from '@console/features/sso/api/use-org-identity-providers'
import {
  downloadSpMetadata,
  importIdPMetadata,
  readMetadataFile,
  type IdPMetadata,
  type IdPMetadataSource,
} from '@console/features/saml/lib/saml-metadata'
import { AdminApiError } from '@console/lib/admin-api/client'
import { emptySamlConfig, type SamlConfig } from '@console/features/saml/types/saml.types'
import { useTranslation } from '@/context/i18n-provider'

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
  const [metadataUrl, setMetadataUrl] = useState('')
  const [isImporting, setIsImporting] = useState(false)
  const [isDownloading, setIsDownloading] = useState(false)
  const [imported, setImported] = useState<IdPMetadata | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  // The SP URLs are built on the API's public address (APP_URL), the same
  // one the API puts in the SP metadata, never on this console's address.
  const { appUrl } = useOrgIdentityProviders(tenantId)

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
    if (!slug || !appUrl) return null
    const base = `${appUrl.replace(/\/+$/, '')}/api/v1/auth/saml/${slug}`
    return {
      metadata: `${base}/metadata`,
      acs: `${base}/acs`,
      login: `${base}/login`,
    }
  }, [tenantSlug, appUrl])

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

  // Fills the IdP fields from the IdP's metadata. Nothing is saved until the
  // administrator saves the form (an owner then approves the change).
  const runImport = async (source: IdPMetadataSource) => {
    setIsImporting(true)
    try {
      const md = await importIdPMetadata(tenantId, source)
      setForm((f) => ({
        ...f,
        idp_entity_id: md.idp_entity_id,
        idp_sso_url: md.idp_sso_url,
        idp_certificate: md.idp_certificate,
      }))
      setImported(md)
      toast.success(
        t(
          'admin.samlConfigForm.metadataImported',
          'Filled in from the metadata. Review the values, then save.'
        )
      )
    } catch (e) {
      setImported(null)
      toast.error(metadataErrorMessage(e, t))
    } finally {
      setIsImporting(false)
    }
  }

  const handleImportUrl = () => {
    const u = metadataUrl.trim()
    if (u) void runImport({ metadata_url: u })
  }

  const handleImportFile = async (file: File | undefined) => {
    if (fileInput.current) fileInput.current.value = ''
    if (!file) return
    const xml = await readMetadataFile(file)
    if (xml === null) {
      toast.error(
        t(
          'admin.samlConfigForm.metadataReason.too_large',
          'The metadata is larger than 1 MB. Check that it is the federation metadata file.'
        )
      )
      return
    }
    void runImport({ metadata_xml: xml })
  }

  const handleDownload = async () => {
    setIsDownloading(true)
    try {
      await downloadSpMetadata(tenantId)
    } catch (e) {
      toast.error(
        getErrorMessage(
          e,
          t(
            'admin.samlConfigForm.spMetadataDownloadFailed',
            'Could not download the service provider metadata'
          )
        )
      )
    } finally {
      setIsDownloading(false)
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
                variant="destructive"
                size="sm"
                className="me-auto"
                onClick={() => setRemoveOpen(true)}
                disabled={isDeleting}
              >
                <Trash2 className="me-2 h-4 w-4" />
                {t('admin.samlConfigForm.removeSaml', 'Remove SAML')}
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
                  {canManage && (
                    <div className="space-y-3 rounded-md border p-3">
                      <div>
                        <p className="text-sm font-medium">
                          {t('admin.samlConfigForm.importFromMetadata', 'Import from metadata')}
                        </p>
                        <p className="text-muted-foreground text-xs">
                          {t(
                            'admin.samlConfigForm.importFromMetadataHint',
                            "Paste the IdP's federation metadata URL (in Microsoft Entra ID: App Federation Metadata Url) or upload its metadata file. The fields below are filled in; nothing is saved until you save."
                          )}
                        </p>
                      </div>
                      <div className="flex flex-col gap-2 sm:flex-row">
                        <Label htmlFor="idp_metadata_url" className="sr-only">
                          {t('admin.samlConfigForm.metadataUrl', 'Metadata URL')}
                        </Label>
                        <Input
                          id="idp_metadata_url"
                          type="url"
                          inputMode="url"
                          value={metadataUrl}
                          onChange={(e) => setMetadataUrl(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              e.preventDefault()
                              handleImportUrl()
                            }
                          }}
                          placeholder="https://login.microsoftonline.com/.../federationmetadata/2007-06/federationmetadata.xml?appid=..."
                          disabled={isImporting}
                        />
                        <Button
                          variant="outline"
                          size="sm"
                          className="shrink-0"
                          onClick={handleImportUrl}
                          disabled={isImporting || !metadataUrl.trim()}
                        >
                          {isImporting && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                          {t('admin.samlConfigForm.import', 'Import')}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="shrink-0"
                          onClick={() => fileInput.current?.click()}
                          disabled={isImporting}
                        >
                          <Upload className="me-2 h-4 w-4" />
                          {t('admin.samlConfigForm.uploadMetadataFile', 'Upload file')}
                        </Button>
                        <input
                          ref={fileInput}
                          type="file"
                          accept=".xml,application/xml,text/xml,application/samlmetadata+xml"
                          className="hidden"
                          data-testid="idp-metadata-file"
                          aria-label={t('admin.samlConfigForm.uploadMetadataFile', 'Upload file')}
                          onChange={(e) => void handleImportFile(e.target.files?.[0])}
                        />
                      </div>
                      {imported && (
                        <p className="text-muted-foreground text-xs" role="status">
                          {t(
                            'admin.samlConfigForm.metadataImportedCertificates',
                            'Signing certificates read: {count}. The first expires on {date}.',
                            {
                              count: imported.certificates.length,
                              date: firstExpiry(imported),
                            }
                          )}
                        </p>
                      )}
                    </div>
                  )}
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
                        'admin.samlConfigForm.idpSigningCertificatesPem',
                        'IdP signing certificates (PEM, one or more)'
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
                    {data?.certificate_not_after && (
                      <CertificateExpiry notAfter={data.certificate_not_after} />
                    )}
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
                      'admin.samlConfigForm.registerTheseUrlsInYourOrUpload',
                      "Upload the metadata file in your IdP's SAML application, or register these URLs there."
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
                      <Separator />
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full"
                        onClick={() => void handleDownload()}
                        disabled={isDownloading}
                      >
                        {isDownloading ? (
                          <Loader2 className="me-2 h-4 w-4 animate-spin" />
                        ) : (
                          <Download className="me-2 h-4 w-4" />
                        )}
                        {t('admin.samlConfigForm.downloadSpMetadata', 'Download SP metadata (XML)')}
                      </Button>
                    </>
                  ) : (
                    <p className="text-muted-foreground text-sm">
                      {t(
                        'admin.ssoSetupGuide.noAppUrl',
                        'The public address of the app is not set. Set APP_URL on the API to see the addresses to register.'
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
          'People can no longer sign in through the identity provider. Make sure they have another way to sign in first. The stored certificate and settings are deleted; you can configure SAML again from scratch.'
        )}
        confirmText={t('confirm.saml.removeButton', 'Remove SAML')}
        typeToConfirm={tenantSlug || undefined}
        destructive
        isLoading={isDeleting}
        handleConfirm={() => void handleDelete()}
      />
    </div>
  )
}

type Translate = ReturnType<typeof useTranslation>['t']

/** The soonest expiry among the imported certificates (YYYY-MM-DD). */
function firstExpiry(md: IdPMetadata): string {
  const dates = md.certificates
    .map((c) => new Date(c.not_after))
    .filter((d) => !Number.isNaN(d.getTime()))
    .sort((a, b) => a.getTime() - b.getTime())
  return dates.length ? dates[0].toISOString().slice(0, 10) : ''
}

/**
 * The refusal of a metadata import, by the API's reason: what is wrong with
 * the document or the address, and what to do.
 */
export function metadataErrorMessage(e: unknown, t: Translate): string {
  const reason =
    e instanceof AdminApiError && e.details && typeof e.details === 'object'
      ? (e.details as { reason?: unknown }).reason
      : undefined
  const messages: Record<string, () => string> = {
    empty: () => t('admin.samlConfigForm.metadataReason.empty', 'The metadata is empty.'),
    too_large: () =>
      t(
        'admin.samlConfigForm.metadataReason.too_large',
        'The metadata is larger than 1 MB. Check that it is the federation metadata file.'
      ),
    doctype: () =>
      t(
        'admin.samlConfigForm.metadataReason.doctype',
        'The metadata declares a document type or entities, which is not accepted.'
      ),
    malformed: () =>
      t('admin.samlConfigForm.metadataReason.malformed', 'The metadata is not valid XML.'),
    not_metadata: () =>
      t(
        'admin.samlConfigForm.metadataReason.not_metadata',
        'This is not the SAML metadata of one identity provider.'
      ),
    no_idp: () =>
      t(
        'admin.samlConfigForm.metadataReason.no_idp',
        'The metadata describes no SAML identity provider. Use the IdP metadata, not a service provider file.'
      ),
    no_entity_id: () =>
      t('admin.samlConfigForm.metadataReason.no_entity_id', 'The metadata has no entity ID.'),
    no_sso_url: () =>
      t(
        'admin.samlConfigForm.metadataReason.no_sso_url',
        'The metadata has no https sign-in URL for the redirect or POST binding.'
      ),
    no_signing_certificate: () =>
      t(
        'admin.samlConfigForm.metadataReason.no_signing_certificate',
        'The metadata has no signing certificate.'
      ),
    invalid_certificate: () =>
      t(
        'admin.samlConfigForm.metadataReason.invalid_certificate',
        'A signing certificate in the metadata cannot be read.'
      ),
    certificate_expired: () =>
      t(
        'admin.samlConfigForm.metadataReason.certificate_expired',
        'Every signing certificate in the metadata has expired. Create a new one at the IdP.'
      ),
    too_many_certificates: () =>
      t(
        'admin.samlConfigForm.metadataReason.too_many_certificates',
        'The metadata has more than 5 signing certificates.'
      ),
    invalid_url: () =>
      t(
        'admin.samlConfigForm.metadataReason.invalid_url',
        'Enter the full https address of the metadata.'
      ),
    url_blocked: () =>
      t(
        'admin.samlConfigForm.metadataReason.url_blocked',
        'This address is not allowed: it points to a private or internal network, or redirects there or to plain http.'
      ),
    unreachable: () =>
      t(
        'admin.samlConfigForm.metadataReason.unreachable',
        'The address did not answer with a document. Check it, or upload the metadata file instead.'
      ),
  }
  if (typeof reason === 'string' && messages[reason]) return messages[reason]()
  return getErrorMessage(
    e,
    t('admin.samlConfigForm.metadataImportFailed', 'Could not read the metadata')
  )
}

/** The stored certificate's expiry; highlighted within 30 days. */
function CertificateExpiry({ notAfter }: { notAfter: string }) {
  const { t } = useTranslation()
  const [now] = useState(() => Date.now())
  const at = new Date(notAfter)
  if (Number.isNaN(at.getTime())) return null
  const days = Math.ceil((at.getTime() - now) / 86_400_000)
  const date = at.toISOString().slice(0, 10)
  if (days <= 0) {
    return (
      <p className="text-destructive text-xs" role="status">
        {t('admin.samlConfigForm.certificateExpired', 'The stored certificate expired on {date}.', {
          date,
        })}
      </p>
    )
  }
  return (
    <p
      className={
        days <= 30 ? 'text-xs text-amber-600 dark:text-amber-400' : 'text-muted-foreground text-xs'
      }
      role="status"
    >
      {t(
        'admin.samlConfigForm.certificateExpires',
        'The stored certificate expires on {date} ({days} days).',
        {
          date,
          days,
        }
      )}
    </p>
  )
}
