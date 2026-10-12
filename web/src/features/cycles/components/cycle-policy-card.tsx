'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { updateCyclePolicy, useCyclePolicy } from '../policy'

/**
 * The organization's cycle close policy, for owners and admins: whether a
 * cycle below the validation coverage SLO can still be closed. Renders
 * nothing for everyone else (the API refuses them too).
 */
export function CyclePolicyCard() {
  const { t } = useTranslation()
  const { data, mutate } = useCyclePolicy()
  const [saving, setSaving] = useState(false)

  if (!data) return null

  const onChange = async (checked: boolean) => {
    setSaving(true)
    try {
      const next = await updateCyclePolicy({ ...data, enforce_coverage_slo: checked })
      await mutate(next, { revalidate: false })
      toast.success(t('validation.cyclePolicy.saved', 'Cycle policy saved'))
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-start justify-between gap-4 rounded-lg border p-4">
      <div className="space-y-1">
        <Label htmlFor="cycle-enforce-coverage-slo" className="font-medium">
          {t(
            'validation.cyclePolicy.enforceLabel',
            'Require the validation coverage SLO to close a cycle'
          )}
        </Label>
        <p className="text-sm text-muted-foreground">
          {t(
            'validation.cyclePolicy.enforceHelp',
            'On: a cycle whose resolved findings lack validation evidence below the coverage targets cannot be closed. Off: it closes and the shortfall stays visible.'
          )}
        </p>
      </div>
      <Switch
        id="cycle-enforce-coverage-slo"
        checked={data.enforce_coverage_slo}
        disabled={saving}
        onCheckedChange={(checked) => void onChange(checked)}
        aria-label={t(
          'validation.cyclePolicy.enforceLabel',
          'Require the validation coverage SLO to close a cycle'
        )}
      />
    </div>
  )
}
