'use client'

import { useState } from 'react'
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
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'

import {
  createScanProfileSchema,
  type CreateScanProfileFormData,
} from '../schemas/scan-profile-schema'
import { useCreateScanProfile, invalidateScanProfilesCache } from '@/lib/api/scan-profile-hooks'
import { createDefaultQualityGate, type QualityGate } from '@/lib/api/scan-profile-types'
import type { RuleSources } from '@/lib/api/scan-types'
import { QualityGateFields } from './quality-gate-fields'
import { RuleSourcesField } from './rule-sources-field'

interface AddScanProfileDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess?: () => void
}

export function AddScanProfileDialog({ open, onOpenChange, onSuccess }: AddScanProfileDialogProps) {
  const { t } = useTranslation()
  const [gate, setGate] = useState<QualityGate>(createDefaultQualityGate())
  const [ruleSources, setRuleSources] = useState<RuleSources>('both')

  const form = useForm<CreateScanProfileFormData>({
    resolver: zodResolver(createScanProfileSchema),
    defaultValues: { name: '', description: '', is_default: false },
  })

  const { trigger: createProfile, isMutating } = useCreateScanProfile()

  const reset = () => {
    form.reset()
    setGate(createDefaultQualityGate())
    setRuleSources('both')
  }

  const onSubmit = async (data: CreateScanProfileFormData) => {
    try {
      await createProfile({ ...data, quality_gate: gate, rule_sources: ruleSources })
      toast.success(t('scans.profiles.created', undefined, { name: data.name }))
      await invalidateScanProfilesCache()
      reset()
      onOpenChange(false)
      onSuccess?.()
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.profiles.createFailed')))
    }
  }

  const handleClose = (isOpen: boolean) => {
    if (!isOpen) reset()
    onOpenChange(isOpen)
  }

  return (
    <Dialog open={open} onOpenChange={handleClose}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.profiles.createTitle')}</DialogTitle>
          <DialogDescription>{t('scans.profiles.createDesc')}</DialogDescription>
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
                        <Input placeholder={t('scans.profiles.namePlaceholder')} {...field} />
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
                <QualityGateFields value={gate} onChange={setGate} idPrefix="add-profile" />
              </div>

              <Separator />

              <RuleSourcesField
                value={ruleSources}
                onChange={setRuleSources}
                idPrefix="add-profile"
              />

              <Separator />

              <FormField
                control={form.control}
                name="is_default"
                render={({ field }) => (
                  <FormItem className="flex items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel>{t('scans.profiles.setDefault')}</FormLabel>
                      <FormDescription>{t('scans.profiles.setDefaultHelp')}</FormDescription>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </FormItem>
                )}
              />
            </DialogBody>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => handleClose(false)}
                disabled={isMutating}
              >
                {t('common.cancel')}
              </Button>
              <Button type="submit" disabled={isMutating}>
                {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {t('scans.profiles.create')}
              </Button>
            </DialogFooter>
          </DialogForm>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
