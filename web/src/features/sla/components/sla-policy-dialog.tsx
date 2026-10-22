'use client'

import { useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
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
import { useTranslation } from '@/context/i18n-provider'
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'

import { PRIORITY_WINDOWS, SEVERITY_WINDOWS } from './sla-windows'
import { buildSlaPolicyPayload } from '../lib/sla-policy-payload'
import { NO_SLA } from '../schemas/sla-policy-schema'

import {
  slaPolicySchema,
  newSlaPolicyForm,
  type SlaPolicyFormData,
} from '../schemas/sla-policy-schema'
import {
  useDefaultSlaPolicyApi,
  useCreateSlaPolicy,
  useUpdateSlaPolicy,
  invalidateSlaPoliciesCache,
  type SlaPolicy,
} from '../api/use-sla-policies-api'

interface SlaPolicyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** When set, the dialog edits this policy; otherwise it creates a new one. */
  policy?: SlaPolicy | null
  onSuccess?: () => void
}

function toFormData(policy: SlaPolicy): SlaPolicyFormData {
  return {
    name: policy.name,
    description: policy.description ?? '',
    is_default: policy.is_default,
    p0_days: policy.p0_days,
    p1_days: policy.p1_days,
    p2_days: policy.p2_days,
    p3_days: policy.p3_days,
    critical_days: policy.critical_days,
    high_days: policy.high_days,
    medium_days: policy.medium_days,
    low_days: policy.low_days,
    info_days: policy.info_days,
    warning_threshold_pct: policy.warning_threshold_pct,
    escalation_enabled: policy.escalation_enabled,
  }
}

export function SlaPolicyDialog({ open, onOpenChange, policy, onSuccess }: SlaPolicyDialogProps) {
  const { t } = useTranslation()
  const isEdit = Boolean(policy)

  // A new policy starts from the windows the API reports as effective (the
  // organization's default policy, else the platform defaults).
  const { data: effective, isLoading: effectiveLoading } = useDefaultSlaPolicyApi()
  const seed = policy ? toFormData(policy) : effective ? newSlaPolicyForm(effective) : undefined

  const form = useForm<SlaPolicyFormData>({
    resolver: zodResolver(slaPolicySchema),
    defaultValues: seed,
  })

  // Re-seed the form whenever the target policy, the effective windows or the
  // open state change. react-hook-form's reset is stable across renders.
  const { reset } = form
  useEffect(() => {
    if (!open) return
    if (policy) reset(toFormData(policy))
    else if (effective) reset(newSlaPolicyForm(effective))
  }, [open, policy, effective, reset])
  const seedMissing = !policy && !effective

  const { trigger: createPolicy, isMutating: isCreating } = useCreateSlaPolicy()
  const { trigger: updatePolicy, isMutating: isUpdating } = useUpdateSlaPolicy()
  const isMutating = isCreating || isUpdating

  const onSubmit = async (data: SlaPolicyFormData) => {
    const payload = buildSlaPolicyPayload(data, isEdit)
    try {
      if (isEdit && policy) {
        await updatePolicy({ id: policy.id, ...payload })
        toast.success(
          t('settings.slaPolicies.dialog.updated', 'Policy "{name}" updated', { name: data.name })
        )
      } else {
        await createPolicy(payload)
        toast.success(
          t('settings.slaPolicies.dialog.created', 'Policy "{name}" created', { name: data.name })
        )
      }
      await invalidateSlaPoliciesCache()
      onOpenChange(false)
      onSuccess?.()
    } catch (err) {
      toast.error(
        getErrorMessage(
          err,
          isEdit
            ? t('settings.slaPolicies.dialog.updateFailed', 'Failed to update SLA policy')
            : t('settings.slaPolicies.dialog.createFailed', 'Failed to create SLA policy')
        )
      )
    }
  }

  const numberChange =
    (field: { onChange: (v: number) => void }) => (e: React.ChangeEvent<HTMLInputElement>) =>
      field.onChange(e.target.value === '' ? NaN : Number(e.target.value))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {isEdit
              ? t('settings.slaPolicies.dialog.titleEdit', 'Edit SLA policy')
              : t('settings.slaPolicies.dialog.titleNew', 'New SLA policy')}
          </DialogTitle>
          <DialogDescription>
            {t(
              'settings.slaPolicies.dialog.description',
              'Set the remediation windows in days. A finding with a CTEM priority class (P0–P3) gets its deadline from the priority window; a finding without a class yet uses its severity window. Saving changes deadlines computed from now on; existing deadlines stay as they are.'
            )}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <DialogForm onSubmit={form.handleSubmit(onSubmit)}>
            <DialogBody className="space-y-6">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('settings.slaPolicies.dialog.name', 'Name')}</FormLabel>
                    <FormControl>
                      <Input
                        placeholder={t(
                          'settings.slaPolicies.dialog.namePlaceholder',
                          'Production SLA'
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
                      {t('settings.slaPolicies.dialog.descriptionLabel', 'Description')}
                    </FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder={t(
                          'settings.slaPolicies.dialog.descriptionPlaceholder',
                          'Applied to production-facing assets'
                        )}
                        className="resize-none"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Separator />

              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-medium">
                    {t(
                      'settings.slaPolicies.dialog.priorityTitle',
                      'Priority-class windows (days)'
                    )}
                  </h4>
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'settings.slaPolicies.dialog.priorityHint',
                      'Used for every finding that has a priority class.'
                    )}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  {PRIORITY_WINDOWS.map((pw) => (
                    <FormField
                      key={pw.key}
                      control={form.control}
                      name={pw.key}
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>{pw.label}</FormLabel>
                          <FormControl>
                            <Input
                              type="number"
                              min={1}
                              max={365}
                              {...field}
                              value={Number.isNaN(field.value) ? '' : field.value}
                              onChange={numberChange(field)}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-medium">
                    {t('settings.slaPolicies.dialog.severityTitle', 'Severity windows (days)')}
                  </h4>
                  <p className="text-xs text-muted-foreground">
                    {t(
                      'settings.slaPolicies.dialog.severityHint',
                      'Used only for findings that have no priority class yet. Info 0 = informational findings get no SLA (the default), whatever their priority class.'
                    )}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
                  {SEVERITY_WINDOWS.map((sev) => (
                    <FormField
                      key={sev.key}
                      control={form.control}
                      name={sev.key}
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="flex items-center gap-1.5">
                            <span
                              className={cn('h-2 w-2 rounded-full', SEVERITY_DOT_COLORS[sev.dot])}
                            />
                            {sev.label}
                          </FormLabel>
                          <FormControl>
                            <Input
                              type="number"
                              min={sev.key === 'info_days' ? NO_SLA : 1}
                              max={365}
                              {...field}
                              value={Number.isNaN(field.value) ? '' : field.value}
                              onChange={numberChange(field)}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  ))}
                </div>
              </div>

              <FormField
                control={form.control}
                name="warning_threshold_pct"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>
                      {t('settings.slaPolicies.dialog.warningLabel', 'Warning threshold (%)')}
                    </FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min={1}
                        max={100}
                        className="max-w-[140px]"
                        {...field}
                        value={Number.isNaN(field.value) ? '' : field.value}
                        onChange={numberChange(field)}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'settings.slaPolicies.dialog.warningHint',
                        'A finding is flagged as "warning" once this percentage of its window has elapsed.'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Separator />

              {!isEdit && (
                <p className="text-sm text-muted-foreground">
                  {t(
                    'settings.slaPolicies.dialog.newNotDefault',
                    'A new policy does not apply to any finding until you make it the default from the policy list.'
                  )}
                </p>
              )}

              <FormField
                control={form.control}
                name="escalation_enabled"
                render={({ field }) => (
                  <FormItem className="flex items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel>
                        {t('settings.slaPolicies.dialog.notifyLabel', 'Deadline notifications')}
                      </FormLabel>
                      <FormDescription>
                        {t(
                          'settings.slaPolicies.dialog.notifyHint',
                          'Notify when a finding reaches the warning threshold and when it breaches its deadline. When off, the SLA status still changes but nobody is notified.'
                        )}
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </FormItem>
                )}
              />

              {seedMissing && (
                <p className="text-sm text-muted-foreground" role="status">
                  {effectiveLoading
                    ? t('settings.slaPolicies.dialog.loading', 'Loading the current windows…')
                    : t(
                        'settings.slaPolicies.dialog.loadFailed',
                        'The current windows could not be loaded; try again in a moment.'
                      )}
                </p>
              )}
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
              <Button type="submit" disabled={isMutating || seedMissing}>
                {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {isEdit
                  ? t('settings.slaPolicies.dialog.save', 'Save changes')
                  : t('settings.slaPolicies.dialog.create', 'Create policy')}
              </Button>
            </DialogFooter>
          </DialogForm>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
