'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { ChevronDown, Loader2, Save, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  createOrgIdentityProvider,
  deleteOrgIdentityProvider,
  updateOrgIdentityProvider,
  useOrgIdentityProviders,
} from '../api/use-org-identity-providers'
import { usePendingSSOChanges } from '@console/features/saml/api/use-saml-config'
import {
  isPendingSSOChange,
  PENDING_SSO_MESSAGE,
} from '@/features/sso-approvals/api/use-sso-changes'
import {
  SSO_PROVIDERS,
  SSO_DEFAULT_ROLES,
  getProviderLabel,
  type IdentityProvider,
  type SSOProviderType,
} from '@/features/sso/types/sso.types'
import { useTranslation } from '@/context/i18n-provider'

interface IdentityProvidersPanelProps {
  /** Organization being configured. */
  tenantId: string
  /** Organization slug, for the SSO sign-in URL. */
  tenantSlug: string
  /** False for a read-only administrator: the forms are shown disabled. */
  canManage: boolean
  /** Called after a provider is saved or removed. */
  onChanged?: () => void
}

/**
 * OIDC identity providers (Microsoft Entra ID, Okta, Google Workspace) for
 * one organization. Configured by the platform administrator in the admin
 * console (RFC-022); this section used to live in the tenant's own settings.
 */
export function IdentityProvidersPanel({
  tenantId,
  tenantSlug,
  canManage,
  onChanged,
}: IdentityProvidersPanelProps) {
  const { t } = useTranslation()
  // SSO Identity Providers state
  const { data: identityProviders, mutate: mutateIdPs } = useOrgIdentityProviders(tenantId)
  const { mutate: mutatePending } = usePendingSSOChanges(tenantId)
  const [ssoExpandedProvider, setSsoExpandedProvider] = useState<SSOProviderType | null>(null)
  const [ssoForms, setSsoForms] = useState<
    Record<
      string,
      {
        display_name: string
        client_id: string
        client_secret: string
        tenant_identifier: string
        allowed_domains: string
        auto_provision: boolean
        default_role: string
        is_active: boolean
      }
    >
  >({})
  const [ssoSaving, setSsoSaving] = useState<string | null>(null)
  const [ssoDeleteTarget, setSsoDeleteTarget] = useState<IdentityProvider | null>(null)

  // SSO helper: get existing provider config by type
  const getIdpByType = (type: SSOProviderType): IdentityProvider | undefined =>
    identityProviders?.find((p) => p.provider === type)

  // SSO helper: get or initialize form state for a provider type
  const getSsoForm = (type: SSOProviderType) => {
    if (ssoForms[type]) return ssoForms[type]
    const existing = getIdpByType(type)
    if (existing) {
      return {
        display_name: existing.display_name,
        client_id: existing.client_id,
        client_secret: '',
        tenant_identifier: existing.tenant_identifier || '',
        allowed_domains: existing.allowed_domains?.join(', ') || '',
        auto_provision: existing.auto_provision,
        default_role: existing.default_role,
        is_active: existing.is_active,
      }
    }
    const info = SSO_PROVIDERS.find((p) => p.value === type)
    return {
      display_name: info?.label || '',
      client_id: '',
      client_secret: '',
      tenant_identifier: '',
      allowed_domains: '',
      auto_provision: true,
      default_role: 'member',
      is_active: true,
    }
  }

  const updateSsoForm = (type: SSOProviderType, field: string, value: string | boolean) => {
    const current = getSsoForm(type)
    setSsoForms((prev) => ({ ...prev, [type]: { ...current, [field]: value } }))
  }

  const handleSaveSSO = async (type: SSOProviderType) => {
    const form = getSsoForm(type)
    if (!form.client_id) {
      toast.error(t('admin.identityProvidersPanel.clientIdIsRequired', 'Client ID is required'))
      return
    }

    setSsoSaving(type)
    try {
      const existing = getIdpByType(type)
      const allowedDomains = form.allowed_domains
        .split(',')
        .map((d) => d.trim())
        .filter(Boolean)

      if (existing) {
        // Update existing
        const res = await updateOrgIdentityProvider(tenantId, existing.id, {
          display_name: form.display_name,
          client_id: form.client_id,
          client_secret: form.client_secret || undefined,
          tenant_identifier: form.tenant_identifier || undefined,
          allowed_domains: allowedDomains,
          auto_provision: form.auto_provision,
          default_role: form.default_role,
          is_active: form.is_active,
        })
        if (isPendingSSOChange(res)) {
          toast.info(t('admin.identityProvidersPanel.pendingChange', PENDING_SSO_MESSAGE))
        } else {
          toast.success(
            t('admin.identityProvidersPanel.providerUpdated', '{provider} updated', {
              provider: getProviderLabel(type),
            })
          )
        }
      } else {
        // Create new
        if (!form.client_secret) {
          toast.error(
            t(
              'admin.identityProvidersPanel.clientSecretIsRequiredFor',
              'Client Secret is required for new providers'
            )
          )
          setSsoSaving(null)
          return
        }
        const res = await createOrgIdentityProvider(tenantId, {
          provider: type,
          display_name: form.display_name,
          client_id: form.client_id,
          client_secret: form.client_secret,
          tenant_identifier: form.tenant_identifier || undefined,
          allowed_domains: allowedDomains.length > 0 ? allowedDomains : undefined,
          auto_provision: form.auto_provision,
          default_role: form.default_role,
        })
        if (isPendingSSOChange(res)) {
          toast.info(t('admin.identityProvidersPanel.pendingChange', PENDING_SSO_MESSAGE))
        } else {
          toast.success(
            t('admin.identityProvidersPanel.providerConfigured', '{provider} configured', {
              provider: getProviderLabel(type),
            })
          )
        }
      }
      await mutateIdPs()
      void mutatePending()
      onChanged?.()
      // Clear form cache so it reloads from API
      setSsoForms((prev) => {
        const next = { ...prev }
        delete next[type]
        return next
      })
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('admin.identityProvidersPanel.failedToSaveProvider', 'Failed to save {provider}', {
            provider: getProviderLabel(type),
          })
        )
      )
    } finally {
      setSsoSaving(null)
    }
  }

  const handleDeleteSSO = async () => {
    if (!ssoDeleteTarget) return
    try {
      await deleteOrgIdentityProvider(tenantId, ssoDeleteTarget.id)
      await mutateIdPs()
      onChanged?.()
      // Clear form cache
      setSsoForms((prev) => {
        const next = { ...prev }
        delete next[ssoDeleteTarget.provider]
        return next
      })
      toast.success(
        t('admin.identityProvidersPanel.providerRemoved', '{provider} removed', {
          provider: getProviderLabel(ssoDeleteTarget.provider),
        })
      )
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('admin.identityProvidersPanel.failedToDeleteProvider', 'Failed to delete provider')
        )
      )
    } finally {
      setSsoDeleteTarget(null)
    }
  }

  return (
    <>
      {/* SSO Identity Providers */}
      <Card>
        <CardHeader>
          <CardTitle>
            {t('admin.identityProvidersPanel.singleSignOnSso', 'Single sign-on (SSO)')}
          </CardTitle>
          <CardDescription>
            {t(
              'admin.identityProvidersPanel.allowMembersToSignIn',
              "Allow members to sign in with your organization's identity provider."
            )}
            {identityProviders && identityProviders.some((p) => p.is_active) && (
              <span className="mt-1 block">
                {t('admin.identityProvidersPanel.ssoLoginUrl', 'SSO login URL:')}{' '}
                <code className="bg-muted rounded px-1 text-xs">/login?org={tenantSlug}</code>
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {SSO_PROVIDERS.map((providerDef) => {
            const existing = getIdpByType(providerDef.value)
            const isConfigured = !!existing
            const isExpanded = ssoExpandedProvider === providerDef.value
            const form = getSsoForm(providerDef.value)
            const isSaving = ssoSaving === providerDef.value

            return (
              <Collapsible
                key={providerDef.value}
                open={isExpanded}
                onOpenChange={(open) => setSsoExpandedProvider(open ? providerDef.value : null)}
              >
                <div className="rounded-lg border">
                  <CollapsibleTrigger asChild>
                    <button
                      type="button"
                      className="flex w-full items-center justify-between p-4 text-start hover:bg-accent/50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div>
                          <p className="font-medium">{providerDef.label}</p>
                          <p className="text-muted-foreground text-xs">{providerDef.description}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {isConfigured ? (
                          <Badge variant={existing.is_active ? 'default' : 'secondary'}>
                            {existing.is_active
                              ? t('admin.identityProvidersPanel.active', 'Active')
                              : t('admin.identityProvidersPanel.inactive', 'Inactive')}
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-muted-foreground">
                            {t('admin.identityProvidersPanel.notConfigured', 'Not configured')}
                          </Badge>
                        )}
                        <ChevronDown
                          className={`h-4 w-4 text-muted-foreground transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                        />
                      </div>
                    </button>
                  </CollapsibleTrigger>

                  <CollapsibleContent>
                    <div className="border-t px-4 pb-4 pt-3 space-y-4">
                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label>
                            {t('admin.identityProvidersPanel.displayName', 'Display name')}
                          </Label>
                          <Input
                            value={form.display_name}
                            onChange={(e) =>
                              updateSsoForm(providerDef.value, 'display_name', e.target.value)
                            }
                            placeholder={t(
                              'admin.identityProvidersPanel.corporateSso',
                              'Corporate SSO'
                            )}
                            disabled={!canManage}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>
                            {providerDef.value === 'entra_id'
                              ? t(
                                  'admin.identityProvidersPanel.directoryTenantId',
                                  'Directory (Tenant) ID'
                                )
                              : providerDef.value === 'okta'
                                ? t('admin.identityProvidersPanel.oktaOrgUrl', 'Okta Org URL')
                                : t(
                                    'admin.identityProvidersPanel.workspaceDomain',
                                    'Workspace domain'
                                  )}
                          </Label>
                          <Input
                            value={form.tenant_identifier}
                            onChange={(e) =>
                              updateSsoForm(providerDef.value, 'tenant_identifier', e.target.value)
                            }
                            placeholder={
                              providerDef.value === 'entra_id'
                                ? 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
                                : providerDef.value === 'okta'
                                  ? 'https://dev-123456.okta.com'
                                  : 'example.com'
                            }
                            disabled={!canManage}
                          />
                        </div>
                      </div>

                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label>{t('admin.identityProvidersPanel.clientId', 'Client ID')}</Label>
                          <Input
                            value={form.client_id}
                            onChange={(e) =>
                              updateSsoForm(providerDef.value, 'client_id', e.target.value)
                            }
                            placeholder={t(
                              'admin.identityProvidersPanel.applicationClientId',
                              'Application (client) ID'
                            )}
                            disabled={!canManage}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>
                            {t('admin.identityProvidersPanel.clientSecret', 'Client secret')}
                          </Label>
                          <Input
                            type="password"
                            value={form.client_secret}
                            onChange={(e) =>
                              updateSsoForm(providerDef.value, 'client_secret', e.target.value)
                            }
                            placeholder={
                              isConfigured
                                ? t(
                                    'admin.identityProvidersPanel.leaveEmptyToKeepCurrent',
                                    'Leave empty to keep current'
                                  )
                                : t(
                                    'admin.identityProvidersPanel.clientSecretValue',
                                    'Client secret value'
                                  )
                            }
                            disabled={!canManage}
                          />
                        </div>
                      </div>

                      <div className="space-y-2">
                        <Label>
                          {t(
                            'admin.identityProvidersPanel.allowedEmailDomains',
                            'Allowed email domains'
                          )}
                        </Label>
                        <Input
                          value={form.allowed_domains}
                          onChange={(e) =>
                            updateSsoForm(providerDef.value, 'allowed_domains', e.target.value)
                          }
                          placeholder={t(
                            'admin.identityProvidersPanel.exampleComCorpExampleCom',
                            'example.com, corp.example.com'
                          )}
                          disabled={!canManage}
                        />
                        <p className="text-muted-foreground text-xs">
                          {t(
                            'admin.identityProvidersPanel.commaSeparatedLeaveEmptyTo',
                            'Comma-separated. Leave empty to allow all domains.'
                          )}
                        </p>
                      </div>

                      <div className="flex items-center justify-between rounded-lg border p-3">
                        <div>
                          <p className="text-sm font-medium">
                            {t(
                              'admin.identityProvidersPanel.autoProvisionUsers',
                              'Auto-provision users'
                            )}
                          </p>
                          <p className="text-muted-foreground text-xs">
                            {t(
                              'admin.identityProvidersPanel.automaticallyAddNewSsoUsers',
                              'Automatically add new SSO users to this team'
                            )}
                          </p>
                        </div>
                        <Switch
                          aria-label={t(
                            'admin.identityProvidersPanel.autoProvisionUsers',
                            'Auto-provision users'
                          )}
                          checked={form.auto_provision}
                          onCheckedChange={(checked) =>
                            updateSsoForm(providerDef.value, 'auto_provision', checked)
                          }
                          disabled={!canManage}
                        />
                      </div>

                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="space-y-2">
                          <Label>
                            {t('admin.identityProvidersPanel.defaultRole', 'Default role')}
                          </Label>
                          <Select
                            value={form.default_role}
                            onValueChange={(value) =>
                              updateSsoForm(providerDef.value, 'default_role', value)
                            }
                            disabled={!canManage}
                          >
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {SSO_DEFAULT_ROLES.map((role) => (
                                <SelectItem key={role.value} value={role.value}>
                                  {role.label}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        {isConfigured && (
                          <div className="space-y-2">
                            <Label>{t('admin.identityProvidersPanel.status', 'Status')}</Label>
                            <div className="flex items-center gap-2 pt-1">
                              <Switch
                                aria-label={t('admin.identityProvidersPanel.status', 'Status')}
                                checked={form.is_active}
                                onCheckedChange={(checked) =>
                                  updateSsoForm(providerDef.value, 'is_active', checked)
                                }
                                disabled={!canManage}
                              />
                              <span className="text-sm">
                                {form.is_active
                                  ? t('admin.identityProvidersPanel.active', 'Active')
                                  : t('admin.identityProvidersPanel.inactive', 'Inactive')}
                              </span>
                            </div>
                          </div>
                        )}
                      </div>

                      {canManage && (
                        <div className="flex items-center justify-between pt-2">
                          {isConfigured ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-destructive hover:text-destructive"
                              onClick={() => setSsoDeleteTarget(existing)}
                            >
                              <Trash2 className="me-2 h-4 w-4" />
                              {t('admin.identityProvidersPanel.remove', 'Remove')}
                            </Button>
                          ) : (
                            <div />
                          )}
                          <Button
                            size="sm"
                            onClick={() => handleSaveSSO(providerDef.value)}
                            disabled={isSaving}
                          >
                            {isSaving ? (
                              <Loader2 className="me-2 h-4 w-4 animate-spin" />
                            ) : (
                              <Save className="me-2 h-4 w-4" />
                            )}
                            {isConfigured
                              ? t('admin.identityProvidersPanel.saveChanges', 'Save changes')
                              : t('admin.identityProvidersPanel.configure', 'Configure')}
                          </Button>
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </div>
              </Collapsible>
            )
          })}
        </CardContent>
      </Card>

      {/* SSO Delete Confirmation */}
      <ConfirmDialog
        open={!!ssoDeleteTarget}
        onOpenChange={(open) => !open && setSsoDeleteTarget(null)}
        title={t('confirm.idp.removeTitle', 'Remove the identity provider {name}?', {
          name: ssoDeleteTarget ? getProviderLabel(ssoDeleteTarget.provider) : '',
        })}
        desc={t(
          'confirm.idp.removeDesc',
          'People can no longer sign in to this organization with it. Make sure they have another way to sign in first. This cannot be undone.'
        )}
        confirmText={t('confirm.remove', 'Remove')}
        destructive
        handleConfirm={() => void handleDeleteSSO()}
      />
    </>
  )
}
