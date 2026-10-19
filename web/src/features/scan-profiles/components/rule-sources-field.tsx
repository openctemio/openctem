'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { RuleSources } from '@/lib/api/scan-types'

export const RULE_SOURCES: RuleSources[] = ['both', 'platform', 'tenant']

interface RuleSourcesFieldProps {
  value: RuleSources
  onChange: (value: RuleSources) => void
  disabled?: boolean
  idPrefix: string
}

/** Which detection rules scans of a profile run (a scan can override it). */
export function RuleSourcesField({ value, onChange, disabled, idPrefix }: RuleSourcesFieldProps) {
  const { t } = useTranslation()
  const id = `${idPrefix}-rule-sources`
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="text-sm font-medium">
        {t('scans.profiles.rules.title')}
      </Label>
      <Select value={value} onValueChange={(v) => onChange(v as RuleSources)} disabled={disabled}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {RULE_SOURCES.map((r) => (
            <SelectItem key={r} value={r}>
              {t(`scans.profiles.rules.${r}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-muted-foreground text-xs">{t('scans.profiles.rules.help')}</p>
    </div>
  )
}
