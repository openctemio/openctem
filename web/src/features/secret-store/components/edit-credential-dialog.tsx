'use client'

import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Eye, EyeOff } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

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
  DialogForm,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'

import {
  useRotateSecretStoreCredential,
  useUpdateSecretStoreCredential,
  invalidateSecretStoreCache,
} from '@/lib/api/secret-store-hooks'
import { CREDENTIAL_TYPE_DISPLAY_NAMES, expiryDateToRFC3339 } from '@/lib/api/secret-store-types'
import type {
  RotateSecretStoreCredentialRequest,
  SecretStoreCredential,
  UpdateSecretStoreCredentialRequest,
} from '@/lib/api/secret-store-types'

// Form schema - matches all credential types
type Translate = ReturnType<typeof useTranslation>['t']

const buildFormSchema = (t: Translate) =>
  z.object({
    name: z.string().min(1, t('scans.credentials.add.nameRequired', 'Name is required')).max(255),
    description: z.string().max(1000).optional(),
    expires_at: z.string().optional(),
    // API Key
    api_key_value: z.string().optional(),
    // Basic Auth
    basic_username: z.string().optional(),
    basic_password: z.string().optional(),
    // Bearer Token
    bearer_token: z.string().optional(),
    // SSH Key
    ssh_private_key: z.string().optional(),
    ssh_passphrase: z.string().optional(),
    // AWS Role
    aws_role_arn: z.string().optional(),
    aws_external_id: z.string().optional(),
    // GCP Service Account
    gcp_json_key: z.string().optional(),
    // Azure Service Principal
    azure_tenant_id: z.string().optional(),
    azure_client_id: z.string().optional(),
    azure_client_secret: z.string().optional(),
    // GitHub App
    github_app_id: z.string().optional(),
    github_installation_id: z.string().optional(),
    github_private_key: z.string().optional(),
    // GitLab Token
    gitlab_token: z.string().optional(),
  })

type FormData = z.infer<ReturnType<typeof buildFormSchema>>

interface EditCredentialDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credential: SecretStoreCredential
  onSuccess?: () => void
}

export function EditCredentialDialog({
  open,
  onOpenChange,
  credential,
  onSuccess,
}: EditCredentialDialogProps) {
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({})
  const [pendingRotation, setPendingRotation] = useState<FormData | null>(null)
  const { t } = useTranslation()

  const form = useForm<FormData>({
    resolver: zodResolver(buildFormSchema(t)),
    defaultValues: {
      name: '',
      description: '',
    },
  })

  const { trigger: updateCredential, isMutating: isUpdating } = useUpdateSecretStoreCredential(
    credential.id
  )
  const { trigger: rotateCredential, isMutating: isRotating } = useRotateSecretStoreCredential(
    credential.id
  )
  const isMutating = isUpdating || isRotating

  // Reset form when credential changes
  useEffect(() => {
    if (credential && open) {
      form.reset({
        name: credential.name,
        description: credential.description || '',
        expires_at: credential.expires_at ? credential.expires_at.split('T')[0] : '',
        // Note: We don't populate secret values for security reasons
        // Users must re-enter them to update
      })
    }
  }, [credential, open, form])

  const toggleShowSecret = (field: string) => {
    setShowSecrets((prev) => ({ ...prev, [field]: !prev[field] }))
  }

  const onSubmit = async (data: FormData, confirmedRotation = false) => {
    // Metadata: send only what changed. Clearing is explicit ('' for the
    // description, null for the expiry), never a silently dropped field.
    const request: UpdateSecretStoreCredentialRequest = {}
    if (data.name !== credential.name) request.name = data.name
    if ((data.description ?? '') !== (credential.description ?? '')) {
      request.description = data.description ?? ''
    }
    const storedExpiry = credential.expires_at ? credential.expires_at.split('T')[0] : ''
    if ((data.expires_at ?? '') !== storedExpiry) {
      request.expires_at = expiryDateToRFC3339(data.expires_at)
    }

    // Secret: a new value replaces the stored one through the rotate endpoint
    // (the metadata PUT never carried it, so "updating" a secret did nothing).
    const rotation: RotateSecretStoreCredentialRequest = {}

    // Add credential-specific data based on type
    switch (credential.credential_type) {
      case 'api_key':
        if (data.api_key_value) {
          rotation.api_key = { key: data.api_key_value }
        }
        break
      case 'basic_auth':
        if (data.basic_username || data.basic_password) {
          rotation.basic_auth = {
            username: data.basic_username || '',
            password: data.basic_password || '',
          }
        }
        break
      case 'bearer_token':
        if (data.bearer_token) {
          rotation.bearer_token = { token: data.bearer_token }
        }
        break
      case 'ssh_key':
        if (data.ssh_private_key) {
          rotation.ssh_key = {
            private_key: data.ssh_private_key,
            passphrase: data.ssh_passphrase || undefined,
          }
        }
        break
      case 'aws_role':
        if (data.aws_role_arn) {
          rotation.aws_role = {
            role_arn: data.aws_role_arn,
            external_id: data.aws_external_id || undefined,
          }
        }
        break
      case 'gcp_service_account':
        if (data.gcp_json_key) {
          rotation.gcp_service_account = { json_key: data.gcp_json_key }
        }
        break
      case 'azure_service_principal':
        if (data.azure_tenant_id || data.azure_client_id || data.azure_client_secret) {
          rotation.azure_service_principal = {
            tenant_id: data.azure_tenant_id || '',
            client_id: data.azure_client_id || '',
            client_secret: data.azure_client_secret || '',
          }
        }
        break
      case 'github_app':
        if (data.github_app_id || data.github_installation_id || data.github_private_key) {
          rotation.github_app = {
            app_id: data.github_app_id || '',
            installation_id: data.github_installation_id || '',
            private_key: data.github_private_key || '',
          }
        }
        break
      case 'gitlab_token':
        if (data.gitlab_token) {
          rotation.gitlab_token = { token: data.gitlab_token }
        }
        break
    }

    const hasMetadata = Object.keys(request).length > 0
    const hasRotation = Object.keys(rotation).length > 0
    if (!hasMetadata && !hasRotation) {
      toast.info(t('scans.credentials.edit.noChanges', 'No changes to save'))
      return
    }

    // A new secret replaces the stored one: confirm before it is sent.
    if (hasRotation && !confirmedRotation) {
      setPendingRotation(data)
      return
    }

    try {
      if (hasMetadata) await updateCredential(request)
      if (hasRotation) await rotateCredential(rotation)
      toast.success(
        hasRotation
          ? t(
              'scans.credentials.edit.rotated',
              'Credential "{name}" rotated: the new secret is used from the next fetch',
              { name: data.name }
            )
          : t('scans.credentials.edit.updated', 'Credential "{name}" updated', { name: data.name })
      )
      await invalidateSecretStoreCache()
      setShowSecrets({})
      onOpenChange(false)
      onSuccess?.()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          t('scans.credentials.edit.updateFailed', 'Failed to update credential')
        )
      )
    }
  }

  const renderCredentialFields = () => {
    switch (credential.credential_type) {
      case 'bearer_token':
        return (
          <FormField
            control={form.control}
            name="bearer_token"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('scans.credentials.field.token', 'Token')}</FormLabel>
                <FormControl>
                  <div className="relative">
                    <Input
                      type={showSecrets.bearer_token ? 'text' : 'password'}
                      placeholder={t(
                        'scans.credentials.edit.newTokenPlaceholder',
                        'Enter new token to update'
                      )}
                      {...field}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0"
                      onClick={() => toggleShowSecret('bearer_token')}
                    >
                      {showSecrets.bearer_token ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        )

      case 'ssh_key':
        return (
          <>
            <FormField
              control={form.control}
              name="ssh_private_key"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.privateKey', 'Private Key')}</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder={t(
                        'scans.credentials.edit.newPrivateKeyPlaceholder',
                        'Enter new private key to update'
                      )}
                      className="font-mono text-xs"
                      rows={6}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="ssh_passphrase"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {t('scans.credentials.field.passphrase', 'Passphrase (optional)')}
                  </FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder={t(
                        'scans.credentials.edit.newPassphrasePlaceholder',
                        'Enter new passphrase to update'
                      )}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )

      case 'api_key':
        return (
          <FormField
            control={form.control}
            name="api_key_value"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('scans.credentials.field.apiKey', 'API Key')}</FormLabel>
                <FormControl>
                  <div className="relative">
                    <Input
                      type={showSecrets.api_key ? 'text' : 'password'}
                      placeholder={t(
                        'scans.credentials.edit.newApiKeyPlaceholder',
                        'Enter new API key to update'
                      )}
                      {...field}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0"
                      onClick={() => toggleShowSecret('api_key')}
                    >
                      {showSecrets.api_key ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        )

      case 'basic_auth':
        return (
          <>
            <FormField
              control={form.control}
              name="basic_username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.username', 'Username')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t(
                        'scans.credentials.edit.newUsernamePlaceholder',
                        'Enter new username to update'
                      )}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="basic_password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.password', 'Password')}</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Input
                        type={showSecrets.basic_password ? 'text' : 'password'}
                        placeholder={t(
                          'scans.credentials.edit.newPasswordPlaceholder',
                          'Enter new password to update'
                        )}
                        {...field}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0"
                        onClick={() => toggleShowSecret('basic_password')}
                      >
                        {showSecrets.basic_password ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )

      case 'aws_role':
        return (
          <>
            <FormField
              control={form.control}
              name="aws_role_arn"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.roleArn', 'Role ARN')}</FormLabel>
                  <FormControl>
                    <Input placeholder="arn:aws:iam::123456789012:role/MyRole" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="aws_external_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {t('scans.credentials.field.externalId', 'External ID (optional)')}
                  </FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t(
                        'scans.credentials.field.externalIdPlaceholder',
                        'External ID for cross-account access'
                      )}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )

      case 'gcp_service_account':
        return (
          <FormField
            control={form.control}
            name="gcp_json_key"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  {t('scans.credentials.field.gcpJsonKey', 'Service Account JSON Key')}
                </FormLabel>
                <FormControl>
                  <Textarea
                    placeholder={t(
                      'scans.credentials.edit.gcpPlaceholder',
                      'Paste the full service-account key JSON'
                    )}
                    className="font-mono text-xs"
                    rows={6}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        )

      case 'azure_service_principal':
        return (
          <>
            <FormField
              control={form.control}
              name="azure_tenant_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.tenantId', 'Tenant ID')}</FormLabel>
                  <FormControl>
                    <Input
                      // i18n-ok: identifier format sample
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="azure_client_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.clientId', 'Client ID')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={t(
                        'scans.credentials.edit.clientIdPlaceholder',
                        'Application (client) ID'
                      )}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="azure_client_secret"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {t('scans.credentials.field.clientSecret', 'Client Secret')}
                  </FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Input
                        type={showSecrets.azure_secret ? 'text' : 'password'}
                        placeholder={t(
                          'scans.credentials.edit.newClientSecretPlaceholder',
                          'Enter new client secret to update'
                        )}
                        {...field}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0"
                        onClick={() => toggleShowSecret('azure_secret')}
                      >
                        {showSecrets.azure_secret ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )

      case 'github_app':
        return (
          <>
            <FormField
              control={form.control}
              name="github_app_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.appId', 'App ID')}</FormLabel>
                  <FormControl>
                    <Input placeholder="123456" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="github_installation_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>
                    {t('scans.credentials.field.installationId', 'Installation ID')}
                  </FormLabel>
                  <FormControl>
                    <Input placeholder="12345678" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="github_private_key"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('scans.credentials.field.privateKey', 'Private Key')}</FormLabel>
                  <FormControl>
                    <Textarea
                      // i18n-ok: PEM format sample
                      placeholder="-----BEGIN RSA PRIVATE KEY-----"
                      className="font-mono text-xs"
                      rows={6}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        )

      case 'gitlab_token':
        return (
          <FormField
            control={form.control}
            name="gitlab_token"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('scans.credentials.field.gitlabToken', 'GitLab Token')}</FormLabel>
                <FormControl>
                  <div className="relative">
                    <Input
                      type={showSecrets.gitlab_token ? 'text' : 'password'}
                      placeholder={t(
                        'scans.credentials.edit.newTokenPlaceholder',
                        'Enter new token to update'
                      )}
                      {...field}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0"
                      onClick={() => toggleShowSecret('gitlab_token')}
                    >
                      {showSecrets.gitlab_token ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        )

      default:
        return null
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.credentials.edit.title', 'Edit credential')}</DialogTitle>
          <DialogDescription>
            {t(
              'scans.credentials.edit.description',
              'Update the credential configuration. Leave secret fields empty to keep existing values.'
            )}
          </DialogDescription>
          <div className="flex items-center gap-2">
            <Badge variant="outline">
              {CREDENTIAL_TYPE_DISPLAY_NAMES[credential.credential_type]}
            </Badge>
          </div>
        </DialogHeader>

        <Form {...form}>
          <DialogForm onSubmit={form.handleSubmit((data) => onSubmit(data))}>
            {/* Basic Info */}
            <DialogBody className="space-y-6">
              <div className="space-y-4">
                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('scans.credentials.add.name', 'Name')}</FormLabel>
                      <FormControl>
                        <Input
                          placeholder={t(
                            'scans.credentials.edit.namePlaceholder',
                            'Credential name'
                          )}
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>
                        {t('scans.credentials.add.descriptionLabel', 'Description (optional)')}
                      </FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={t(
                            'scans.credentials.edit.descriptionPlaceholder',
                            'Describe what this credential is used for'
                          )}
                          className="resize-none"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="expires_at"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>
                        {t('scans.credentials.add.expiry', 'Expiration Date (optional)')}
                      </FormLabel>
                      <FormControl>
                        <Input type="date" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <Separator />

              {/* Credential-specific fields */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium">
                  {t('scans.credentials.edit.updateType', 'Update {type}', {
                    type: CREDENTIAL_TYPE_DISPLAY_NAMES[credential.credential_type],
                  })}
                </h4>

                <Alert>
                  <AlertDescription>
                    {t(
                      'scans.credentials.edit.keepHint',
                      'Leave fields empty to keep the current values. Enter new values to update.'
                    )}
                  </AlertDescription>
                </Alert>

                {renderCredentialFields()}
              </div>
            </DialogBody>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isMutating}
              >
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={isMutating}>
                {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('scans.credentials.edit.save', 'Save changes')}
              </Button>
            </DialogFooter>
          </DialogForm>
        </Form>
      </DialogContent>
      <ConfirmDialog
        open={pendingRotation !== null}
        onOpenChange={(next) => !next && setPendingRotation(null)}
        destructive
        title={t('confirm.secretStore.rotateTitle', undefined, { name: credential.name })}
        desc={t('confirm.secretStore.rotateDesc')}
        confirmText={t('confirm.secretStore.rotateBtn')}
        handleConfirm={async () => {
          const data = pendingRotation
          setPendingRotation(null)
          if (data) await onSubmit(data, true)
        }}
      />
    </Dialog>
  )
}
