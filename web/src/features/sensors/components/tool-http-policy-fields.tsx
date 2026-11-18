'use client'

import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsBlock, SettingsRow } from '@/features/shared'
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
    <div data-testid="tool-http-policy-fields">
      <SettingsRow
        label={
          <label htmlFor="tenant-tool-insecure-tls">{t('sensors.httpPolicy.tls.label')}</label>
        }
        hintId="tenant-tool-insecure-tls-desc"
        hint={t('sensors.httpPolicy.tls.help')}
      >
        <Switch
          id="tenant-tool-insecure-tls"
          aria-describedby="tenant-tool-insecure-tls-desc"
          checked={value.forbid_tool_insecure_tls}
          onCheckedChange={(checked) => onChange({ ...value, forbid_tool_insecure_tls: checked })}
          disabled={disabled}
        />
      </SettingsRow>
      <SettingsBlock>
        <p className="text-cap text-muted-foreground">
          {t('sensors.httpPolicy.uaMoved', 'The User-Agent and headers your scans send are set in')}{' '}
          <Link
            href="/settings/scanning/identification"
            className="font-medium underline-offset-2 hover:underline"
          >
            {t('settings.item.scan-identification', 'Scan identification')}
          </Link>
          .
        </p>
      </SettingsBlock>
    </div>
  )
}
