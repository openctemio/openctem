'use client'

import { CAPABILITY_COLOR_CHOICES, capabilitySwatch } from '@/lib/capability-colors'
import { TAG_SWATCH_CLASS } from '@/lib/tag-colors'
import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

import { useTranslation } from '@/context/i18n-provider'
import { getCategoryOptions, getIconOptions } from './capability-options'
import { useUpdateCapability } from '@/lib/api/capability-hooks'
import type { Capability } from '@/lib/api/capability-types'

const updateCapabilitySchema = z.object({
  display_name: z
    .string()
    .min(2, 'Display name must be at least 2 characters')
    .max(100, 'Display name must be at most 100 characters'),
  description: z.string().max(500, 'Description must be at most 500 characters').optional(),
  icon: z.string(),
  color: z.string(),
  category: z.string().optional(),
})

type UpdateCapabilityFormData = z.infer<typeof updateCapabilitySchema>

const COLOR_OPTIONS = CAPABILITY_COLOR_CHOICES.map((value) => ({
  value,
  label: value.charAt(0).toUpperCase() + value.slice(1),
}))

interface EditCapabilityDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  capability: Capability
  onSuccess?: () => void
}

export function EditCapabilityDialog({
  open,
  onOpenChange,
  capability,
  onSuccess,
}: EditCapabilityDialogProps) {
  const { t } = useTranslation()
  const ICON_OPTIONS = getIconOptions(t)
  const CATEGORY_OPTIONS = getCategoryOptions(t)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const { trigger: updateCapability } = useUpdateCapability(capability.id)

  const form = useForm<UpdateCapabilityFormData>({
    resolver: zodResolver(updateCapabilitySchema),
    defaultValues: {
      display_name: capability.display_name,
      description: capability.description || '',
      icon: capability.icon || 'zap',
      color: capabilitySwatch(capability.color),
      category: capability.category,
    },
  })

  // Reset form when capability changes
  useEffect(() => {
    form.reset({
      display_name: capability.display_name,
      description: capability.description || '',
      icon: capability.icon || 'zap',
      color: capabilitySwatch(capability.color),
      category: capability.category,
    })
  }, [capability, form])

  const handleSubmit = async (data: UpdateCapabilityFormData) => {
    setIsSubmitting(true)
    try {
      await updateCapability(data)
      toast.success(
        t('scans.capabilities.toast.updated', 'Capability "{name}" updated', {
          name: data.display_name,
        })
      )
      onOpenChange(false)
      onSuccess?.()
    } catch (err) {
      toast.error(getErrorMessage(err, 'Failed to update capability'))
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('scans.capabilities.dialog.editTitle', 'Edit capability')}</DialogTitle>
          <DialogDescription>
            {t(
              'scans.capabilities.dialog.editDescription',
              'Update the capability details. The code name cannot be changed.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-4">
                <div className="rounded-md bg-muted/50 p-3">
                  <p className="text-sm text-muted-foreground">
                    Code: <code className="font-medium">{capability.name}</code>
                  </p>
                </div>

                <FormField
                  control={form.control}
                  name="display_name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>
                        {t('scans.capabilities.dialog.displayName', 'Display name')}
                      </FormLabel>
                      <FormControl>
                        <Input
                          placeholder={t(
                            'scans.capabilities.dialog.displayNamePlaceholder',
                            'e.g., Web application security'
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
                        {t('scans.capabilities.dialog.description', 'Description')}
                      </FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder={t(
                            'scans.capabilities.dialog.descriptionPlaceholder',
                            'Describe what this capability represents...'
                          )}
                          rows={3}
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Responsive: stack on mobile, 3 cols on sm+ */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <FormField
                    control={form.control}
                    name="category"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('scans.capabilities.dialog.category', 'Category')}</FormLabel>
                        <Select onValueChange={field.onChange} value={field.value}>
                          <FormControl>
                            <SelectTrigger className="w-full">
                              <SelectValue
                                placeholder={t('scans.capabilities.dialog.select', 'Select')}
                              />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {CATEGORY_OPTIONS.map((opt) => (
                              <SelectItem key={opt.value} value={opt.value}>
                                {opt.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="icon"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('scans.capabilities.dialog.icon', 'Icon')}</FormLabel>
                        <Select onValueChange={field.onChange} value={field.value}>
                          <FormControl>
                            <SelectTrigger className="w-full">
                              <SelectValue
                                placeholder={t('scans.capabilities.dialog.select', 'Select')}
                              />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {ICON_OPTIONS.map((opt) => (
                              <SelectItem key={opt.value} value={opt.value}>
                                {opt.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="color"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('scans.capabilities.dialog.color', 'Color')}</FormLabel>
                        <Select onValueChange={field.onChange} value={field.value}>
                          <FormControl>
                            <SelectTrigger className="w-full">
                              <SelectValue
                                placeholder={t('scans.capabilities.dialog.select', 'Select')}
                              />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {COLOR_OPTIONS.map((opt) => (
                              <SelectItem key={opt.value} value={opt.value}>
                                <span className="inline-flex items-center gap-2">
                                  <span
                                    aria-hidden
                                    className={`size-2 rounded-full ${TAG_SWATCH_CLASS[opt.value]}`}
                                  />
                                  {opt.label}
                                </span>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </form>
            </Form>
          </div>
        </DialogBody>
        <DialogFooter className="flex-col sm:flex-row">
          <Button
            type="button"
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={isSubmitting}
            className="w-full sm:w-auto"
          >
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            type="submit"
            disabled={isSubmitting}
            onClick={form.handleSubmit(handleSubmit)}
            className="w-full sm:w-auto"
          >
            {isSubmitting && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('scans.capabilities.dialog.saveChanges', 'Save changes')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
