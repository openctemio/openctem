'use client'

/**
 * The format choice of the import dialog: detect it from the file, or read
 * the file with one of the organization's saved import mappings
 * (features/import-mappings). Shown only to people who may list mappings
 * (integrations:read or assets:import) and only when there is one; it mounts
 * with the open dialog, so a closed dialog asks for nothing.
 */

import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { Permission, useHasAnyPermission } from '@/lib/permissions'
import { useImportMappings } from '@/features/import-mappings/api/import-mappings-api'

const DETECT = '__detect__'

export function MappingFormatField({
  value,
  onChange,
}: {
  /** `mapping:<name>`, or empty to detect the format. */
  value: string
  onChange: (value: string) => void
}) {
  const { t } = useTranslation()
  const canList = useHasAnyPermission(Permission.IntegrationsRead, Permission.AssetsImport)
  const { data } = useImportMappings(canList)
  const mappings = data?.items ?? []
  if (mappings.length === 0) return null

  return (
    <div className="space-y-1">
      <Label htmlFor="import-format">{t('findings.importResults.format', 'Format')}</Label>
      <Select value={value || DETECT} onValueChange={(v) => onChange(v === DETECT ? '' : v)}>
        <SelectTrigger id="import-format" className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={DETECT}>
            {t('findings.importResults.formatDetect', 'Detect from the file')}
          </SelectItem>
          {mappings.map((m) => (
            <SelectItem key={m.id} value={`mapping:${m.name}`}>
              {t('findings.importResults.formatMapping', 'Import mapping: {name}', {
                name: m.name,
              })}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {value && (
        <p className="text-muted-foreground text-xs">
          {t(
            'findings.importResults.formatMappingHint',
            'The file is read with the latest version of this mapping. A mapped import never resolves findings missing from the file.'
          )}
        </p>
      )}
    </div>
  )
}
