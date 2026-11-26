'use client'

import { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Loader2, Settings, Eye, EyeOff } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { z } from 'zod'

import { Button } from '@/components/ui/button'
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
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'

import { ProviderIcon } from './provider-icon'
import type { Integration } from '@/features/integrations'
import type { SCMConnection } from '@/features/repositories/types/repository.types'
import { SCM_PROVIDER_LABELS } from '@/features/assets/types/asset.types'
import {
  useUpdateIntegrationApi,
  useTestIntegrationApi,
  invalidateSCMIntegrationsCache,
} from '@/features/integrations'
import { getErrorMessage } from '@/lib/api/error-handler'

// Helper to get scmOrganization from either Integration or SCMConnection
function getScmOrganization(connection: Integration | SCMConnection): string {
  // SCMConnection uses camelCase
  if ('scmOrganization' in connection && connection.scmOrganization) {
    return connection.scmOrganization
  }
  // Integration uses scm_extension
  if ('scm_extension' in connection && connection.scm_extension?.scm_organization) {
    return connection.scm_extension.scm_organization
  }
  return ''
}

const editConnectionSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name must be less than 100 characters'),
  accessToken: z.string().max(500, 'Token is too long').optional(),
  scmOrganization: z
    .string()
    .max(100, 'Organization name must be less than 100 characters')
    .optional(),
})

type EditConnectionFormData = z.infer<typeof editConnectionSchema>

interface EditConnectionDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  connection: Integration | SCMConnection
  onSuccess?: () => void
}

export function EditConnectionDialog({
  open,
  onOpenChange,
  connection,
  onSuccess,
}: EditConnectionDialogProps) {
  const { t } = useTranslation()
  const [showToken, setShowToken] = useState(false)

  const initialScmOrganization = getScmOrganization(connection)

  const form = useForm<EditConnectionFormData>({
    resolver: zodResolver(editConnectionSchema),
    defaultValues: {
      name: connection.name,
      accessToken: '',
      scmOrganization: initialScmOrganization,
    },
  })

  const { trigger: updateConnection, isMutating: isUpdating } = useUpdateIntegrationApi(
    connection.id
  )
  const { trigger: validateConnection, isMutating: isValidating } = useTestIntegrationApi(
    connection.id
  )

  // Reset form when dialog opens or connection changes
  useEffect(() => {
    if (open) {
      form.reset({
        name: connection.name,
        accessToken: '',
        scmOrganization: getScmOrganization(connection),
      })
      setShowToken(false)
    }
  }, [open, connection, form])

  const onSubmit = async (data: EditConnectionFormData) => {
    try {
      // Only include fields that have changed
      const updateData: { name?: string; credentials?: string; scm_organization?: string } = {}
      const currentScmOrganization = getScmOrganization(connection)

      if (data.name !== connection.name) {
        updateData.name = data.name
      }
      if (data.accessToken && data.accessToken.length > 0) {
        updateData.credentials = data.accessToken
      }
      if (data.scmOrganization !== currentScmOrganization) {
        // Send the literal value (including "") so clearing the org actually
        // persists — `|| undefined` omitted it from the body and the backend
        // treats a nil pointer as "no change", making the org un-clearable.
        updateData.scm_organization = data.scmOrganization ?? ''
      }

      // Only call API if there are changes
      if (Object.keys(updateData).length === 0) {
        toast.info(t('scmConnections.edit.noChanges', 'No changes to save'))
        onOpenChange(false)
        return
      }

      await updateConnection(updateData)

      // If token was updated, test the connection
      if (updateData.credentials) {
        toast.info(t('scmConnections.edit.testing', 'Testing updated credentials...'))
        try {
          const result = await validateConnection()
          if (result?.status === 'connected') {
            toast.success(
              t('scmConnections.edit.verified', 'Connection "{name}" updated and verified.', {
                name: data.name,
              })
            )
          } else {
            toast.warning(
              t(
                'scmConnections.edit.verifyFailedReason',
                'Connection updated but verification failed: {reason}',
                {
                  reason:
                    result?.status_message ||
                    t('scmConnections.edit.unknownError', 'Unknown error'),
                }
              )
            )
          }
        } catch {
          toast.warning(
            t('scmConnections.edit.verifyFailed', 'Connection updated but verification failed')
          )
        }
      } else {
        toast.success(
          t('scmConnections.edit.updated', 'Connection "{name}" updated.', {
            name: data.name,
          })
        )
      }

      await invalidateSCMIntegrationsCache()
      onOpenChange(false)
      onSuccess?.()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('scmConnections.edit.updateFailed', 'Failed to update connection'))
      )
    }
  }

  const handleClose = () => {
    form.reset()
    setShowToken(false)
    onOpenChange(false)
  }

  const isSaving = isUpdating || isValidating

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            {t('scmIntegration.actions.editConnection', 'Edit connection')}
          </DialogTitle>
          <DialogDescription className="flex items-center gap-2">
            <ProviderIcon provider={connection.provider} className="h-4 w-4" />
            {SCM_PROVIDER_LABELS[connection.provider as keyof typeof SCM_PROVIDER_LABELS] ||
              connection.provider}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <DialogForm onSubmit={form.handleSubmit(onSubmit)}>
            {/* Connection Name */}
            <DialogBody className="space-y-4">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('scmConnections.field.name', 'Connection name')}</FormLabel>
                    <FormControl>
                      <Input
                        placeholder={t(
                          'scmConnections.field.namePlaceholder',
                          'e.g., My GitHub Enterprise'
                        )}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'scmConnections.field.nameHelp',
                        'A friendly name to identify this connection'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Organization (optional) */}
              <FormField
                control={form.control}
                name="scmOrganization"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {t('scmConnections.field.organization', 'Organization or group (optional)')}
                    </FormLabel>
                    <FormControl>
                      <Input
                        placeholder={t(
                          'scmConnections.field.organizationPlaceholder',
                          'e.g., my-org'
                        )}
                        {...field}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'scmConnections.field.organizationHelp',
                        'Limit repositories to a specific organization or group'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Access Token */}
              <FormField
                control={form.control}
                name="accessToken"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {t('scmConnections.field.token', 'Personal access token')}
                    </FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input
                          type={showToken ? 'text' : 'password'}
                          placeholder={t(
                            'scmConnections.edit.tokenPlaceholder',
                            'Leave empty to keep current token'
                          )}
                          className="pe-10"
                          {...field}
                        />
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon-sm"
                          className="absolute right-0 top-1/2 -translate-y-1/2 px-3 py-2 hover:bg-transparent"
                          onClick={() => setShowToken(!showToken)}
                        >
                          {showToken ? (
                            <EyeOff className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <Eye className="h-4 w-4 text-muted-foreground" />
                          )}
                        </Button>
                      </div>
                    </FormControl>
                    <FormDescription>
                      {t(
                        'scmConnections.edit.tokenHelp',
                        'Enter a new token to update credentials, or leave empty to keep current'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </DialogBody>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={handleClose} disabled={isSaving}>
                {t('common.cancel', 'Cancel')}
              </Button>
              <Button type="submit" disabled={isSaving}>
                {isSaving ? <Loader2 className="me-2 h-4 w-4 animate-spin" /> : null}
                {t('scmConnections.edit.save', 'Save changes')}
              </Button>
            </DialogFooter>
          </DialogForm>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
