'use client'

import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'

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
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Separator } from '@/components/ui/separator'

import {
  updateScanProfileSchema,
  type UpdateScanProfileFormData,
} from '../schemas/scan-profile-schema'
import { useUpdateScanProfile, invalidateScanProfilesCache } from '@/lib/api/scan-profile-hooks'
import type { QualityGate, ScanProfile } from '@/lib/api/scan-profile-types'
import { QualityGateFields } from './quality-gate-fields'

interface EditScanProfileDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  profile: ScanProfile
  onSuccess?: () => void
}

export function EditScanProfileDialog({
  open,
  onOpenChange,
  profile,
  onSuccess,
}: EditScanProfileDialogProps) {
  const { t } = useTranslation()
  const [gate, setGate] = useState<QualityGate>(profile.quality_gate)

  const form = useForm<UpdateScanProfileFormData>({
    resolver: zodResolver(updateScanProfileSchema),
    defaultValues: { name: profile.name, description: profile.description || '' },
  })

  const { trigger: updateProfile, isMutating } = useUpdateScanProfile(profile.id)

  // Reset the form when another profile is opened.
  useEffect(() => {
    setGate(profile.quality_gate)
    form.reset({ name: profile.name, description: profile.description || '' })
  }, [profile, form])

  const onSubmit = async (data: UpdateScanProfileFormData) => {
    try {
      await updateProfile({ ...data, quality_gate: gate })
      toast.success(t('scans.profiles.updated', undefined, { name: data.name || profile.name }))
      await invalidateScanProfilesCache()
      onOpenChange(false)
      onSuccess?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.profiles.updateFailed')))
    }
  }

  const isSystemProfile = profile.is_system

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.profiles.editTitle')}</DialogTitle>
          <DialogDescription>
            {isSystemProfile ? t('scans.profiles.systemReadOnly') : t('scans.profiles.editDesc')}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <DialogForm onSubmit={form.handleSubmit(onSubmit)}>
            <DialogBody className="space-y-6">
              <div className="space-y-4">
                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('scans.profiles.name')}</FormLabel>
                      <FormControl>
                        <Input
                          placeholder={t('scans.profiles.namePlaceholder')}
                          disabled={isSystemProfile}
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
                      <FormLabel>{t('scans.profiles.description')}</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={t('scans.profiles.descriptionPlaceholder')}
                          className="resize-none"
                          disabled={isSystemProfile}
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <Separator />

              <div className="space-y-3">
                <h4 className="text-sm font-medium">{t('scans.profiles.gate.title')}</h4>
                <QualityGateFields
                  value={gate}
                  onChange={setGate}
                  disabled={isSystemProfile}
                  idPrefix="edit-profile"
                />
              </div>
            </DialogBody>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isMutating}
              >
                {t('common.cancel')}
              </Button>
              {/* A system profile is read-only: no save action to offer. */}
              {!isSystemProfile && (
                <Button type="submit" disabled={isMutating}>
                  {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                  {t('scans.profiles.save')}
                </Button>
              )}
            </DialogFooter>
          </DialogForm>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
