'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

export interface ToolHTTPPolicyValue {
  forbid_tool_insecure_tls: boolean
}

/**
 * The organization's TLS rule for its scan tools (api RFC-060 §4.1), sent
 * with every scan job. It only narrows: a sensor's local policy decides
 * first. The User-Agent and headers are on the Scan identification page.
 */
export function ToolHTTPPolicyFields({
  value,
  onChange,
  disabled,
}: {
  value: ToolHTTPPolicyValue
  onChange: (next: ToolHTTPPolicyValue) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-4" data-testid="tool-http-policy-fields">
      <div className="flex items-center justify-between gap-4">
        <div className="space-y-0.5">
          <Label htmlFor="tenant-tool-insecure-tls">{t('sensors.httpPolicy.tls.label')}</Label>
          <p className="text-sm text-muted-foreground" id="tenant-tool-insecure-tls-desc">
            {t('sensors.httpPolicy.tls.help')}
          </p>
        </div>
        <Switch
          id="tenant-tool-insecure-tls"
          aria-describedby="tenant-tool-insecure-tls-desc"
          checked={value.forbid_tool_insecure_tls}
          onCheckedChange={(checked) => onChange({ ...value, forbid_tool_insecure_tls: checked })}
          disabled={disabled}
        />
      </div>
      <p className="text-sm text-muted-foreground">
        {t('sensors.httpPolicy.uaMoved', 'The User-Agent and headers your scans send are set in')}{' '}
        <Link
          href="/settings/scanning/identification"
          className="font-medium underline-offset-2 hover:underline"
        >
          {t('settings.item.scan-identification', 'Scan identification')}
        </Link>
        .
      </p>
    </div>
  )
}
