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
import { SEVERITY_DOT_COLORS } from '@/lib/severity-colors'
import { cn } from '@/lib/utils'

import { PRIORITY_WINDOWS, SEVERITY_WINDOWS } from './sla-windows'
import { NO_SLA } from '../schemas/sla-policy-schema'

import {
  slaPolicySchema,
  DEFAULT_SLA_FORM,
  type SlaPolicyFormData,
} from '../schemas/sla-policy-schema'
import {
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
  const isEdit = Boolean(policy)

  const form = useForm<SlaPolicyFormData>({
    resolver: zodResolver(slaPolicySchema),
    defaultValues: DEFAULT_SLA_FORM,
  })

  // Re-seed the form whenever the target policy (or open state) changes.
  // react-hook-form's reset is stable across renders, so it adds no re-runs.
  const { reset } = form
  useEffect(() => {
    if (open) {
      reset(policy ? toFormData(policy) : DEFAULT_SLA_FORM)
    }
  }, [open, policy, reset])

  const { trigger: createPolicy, isMutating: isCreating } = useCreateSlaPolicy()
  const { trigger: updatePolicy, isMutating: isUpdating } = useUpdateSlaPolicy()
  const isMutating = isCreating || isUpdating

  const onSubmit = async (data: SlaPolicyFormData) => {
    const payload = {
      name: data.name,
      // An empty string clears the description (absent would keep the old one).
      description: data.description ?? '',
      // Only the default policy governs findings today (asset overrides have no
      // editor yet), so a new policy is always the default.
      is_default: isEdit ? data.is_default : true,
      p0_days: data.p0_days,
      p1_days: data.p1_days,
      p2_days: data.p2_days,
      p3_days: data.p3_days,
      critical_days: data.critical_days,
      high_days: data.high_days,
      medium_days: data.medium_days,
      low_days: data.low_days,
      info_days: data.info_days,
      warning_threshold_pct: data.warning_threshold_pct,
      escalation_enabled: data.escalation_enabled,
    }
    try {
      if (isEdit && policy) {
        await updatePolicy({ id: policy.id, ...payload })
        toast.success(`Policy "${data.name}" updated`)
      } else {
        await createPolicy(payload)
        toast.success(`Policy "${data.name}" created`)
      }
      await invalidateSlaPoliciesCache()
      onOpenChange(false)
      onSuccess?.()
    } catch (err) {
      toast.error(getErrorMessage(err, `Failed to ${isEdit ? 'update' : 'create'} SLA policy`))
    }
  }

  const numberChange =
    (field: { onChange: (v: number) => void }) => (e: React.ChangeEvent<HTMLInputElement>) =>
      field.onChange(e.target.value === '' ? NaN : Number(e.target.value))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit SLA Policy' : 'New SLA Policy'}</DialogTitle>
          <DialogDescription>
            Set the remediation windows in days. A finding with a CTEM priority class (P0–P3) gets
            its deadline from the priority window; a finding without a class yet uses its severity
            window. Saving changes deadlines computed from now on; existing deadlines stay as they
            are.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="Production SLA" {...field} />
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
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea
                      placeholder="Applied to production-facing assets"
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
                <h4 className="text-sm font-medium">Priority-class windows (days)</h4>
                <p className="text-xs text-muted-foreground">
                  Used for every finding that has a priority class.
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
                <h4 className="text-sm font-medium">Severity windows (days)</h4>
                <p className="text-xs text-muted-foreground">
                  Used only for findings that have no priority class yet. Info 0 = informational
                  findings get no SLA (the default), whatever their priority class.
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
                  <FormLabel>Warning threshold (%)</FormLabel>
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
                    A finding is flagged &quot;warning&quot; once this percentage of its window has
                    elapsed.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Separator />

            {/* Only an existing non-default policy can be promoted; the default
                cannot be demoted here (that would leave no policy in force). */}
            {isEdit && policy && !policy.is_default && (
              <FormField
                control={form.control}
                name="is_default"
                render={({ field }) => (
                  <FormItem className="flex items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel>Make this the default policy</FormLabel>
                      <FormDescription>
                        This policy applies to nothing until it is the default. The current default
                        stops applying.
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </FormItem>
                )}
              />
            )}

            <FormField
              control={form.control}
              name="escalation_enabled"
              render={({ field }) => (
                <FormItem className="flex items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <FormLabel>Deadline notifications</FormLabel>
                    <FormDescription>
                      Notify when a finding reaches the warning threshold and when it breaches its
                      deadline. When off, the SLA status still changes but nobody is notified.
                    </FormDescription>
                  </div>
                  <FormControl>
                    <Switch checked={field.value} onCheckedChange={field.onChange} />
                  </FormControl>
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isMutating}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isMutating}>
                {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
                {isEdit ? 'Save changes' : 'Create policy'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
