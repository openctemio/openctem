/**
 * Detection rules: which rules a template-driven scan (nuclei, semgrep,
 * opengrep, betterleaks, gitleaks) runs, the platform's, the organization's
 * own templates, or both, and which of the organization's templates.
 * Shown by the Options step only for those scanners.
 */

'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Permission, useHasPermission } from '@/lib/permissions'
import { useScannerTemplates } from '@/lib/api/scanner-template-hooks'
import type { TemplateType } from '@/lib/api/scanner-template-types'
import type { RuleSources } from '@/lib/api/scan-types'

/** Select value of "inherit" (the form keeps ''); Radix items cannot be empty. */
const INHERIT = 'inherit'
const TEMPLATES_PAGE = '/settings/scanning/templates'

interface RuleSourcesSectionProps {
  templateType: TemplateType
  ruleSources: '' | RuleSources
  customTemplateIds: string[]
  onChange: (data: { ruleSources?: '' | RuleSources; customTemplateIds?: string[] }) => void
  error?: string | null
}

export function RuleSourcesSection({
  templateType,
  ruleSources,
  customTemplateIds,
  onChange,
  error,
}: RuleSourcesSectionProps) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.ScannerTemplatesRead)
  const showList = ruleSources !== 'platform'
  const enabled = canRead && showList
  const { data, isLoading } = useScannerTemplates(
    enabled ? { template_type: templateType, status: 'active', per_page: 100 } : undefined,
    { revalidateOnFocus: false, isPaused: () => !enabled }
  )
  const templates = data?.items ?? []

  const toggle = (id: string, checked: boolean) => {
    const next = checked
      ? [...new Set([...customTemplateIds, id])]
      : customTemplateIds.filter((x) => x !== id)
    onChange({ customTemplateIds: next })
  }

  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{t('scans.rules.title')}</legend>
      <Label htmlFor="rule-sources" className="sr-only">
        {t('scans.rules.sources')}
      </Label>
      <Select
        value={ruleSources === '' ? INHERIT : ruleSources}
        onValueChange={(v) => onChange({ ruleSources: v === INHERIT ? '' : (v as RuleSources) })}
      >
        <SelectTrigger id="rule-sources" className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={INHERIT}>{t('scans.rules.inherit')}</SelectItem>
          <SelectItem value="both">{t('scans.rules.both')}</SelectItem>
          <SelectItem value="platform">{t('scans.rules.platform')}</SelectItem>
          <SelectItem value="tenant">{t('scans.rules.tenant')}</SelectItem>
        </SelectContent>
      </Select>
      <p className="text-muted-foreground text-xs">{t('scans.rules.help')}</p>

      {showList &&
        (!canRead ? (
          <p className="text-muted-foreground text-xs">{t('scans.rules.noAccess')}</p>
        ) : isLoading ? (
          <p className="text-muted-foreground text-xs">{t('scans.rules.loading')}</p>
        ) : templates.length === 0 ? (
          <p className="text-muted-foreground rounded-md border border-dashed p-3 text-xs">
            {t('scans.rules.empty')}{' '}
            <Link href={TEMPLATES_PAGE} className="text-primary underline">
              {t('scans.rules.manage')}
            </Link>
          </p>
        ) : (
          <div
            role="group"
            aria-label={t('scans.rules.templates')}
            className="max-h-48 space-y-1 overflow-y-auto rounded-md border p-2"
          >
            {templates.map((tpl) => {
              const id = `rule-template-${tpl.id}`
              return (
                <label
                  key={tpl.id}
                  htmlFor={id}
                  className="flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-sm hover:bg-muted/50"
                >
                  <Checkbox
                    id={id}
                    checked={customTemplateIds.includes(tpl.id)}
                    onCheckedChange={(c) => toggle(tpl.id, c === true)}
                  />
                  <span className="min-w-0 flex-1 truncate">{tpl.name}</span>
                  <span className="text-muted-foreground text-xs">
                    {t('scans.rules.ruleCount', undefined, { count: tpl.rule_count })}
                  </span>
                </label>
              )
            })}
          </div>
        ))}
      {error && (
        <p role="alert" className="text-destructive text-xs">
          {error}
        </p>
      )}
    </fieldset>
  )
}
