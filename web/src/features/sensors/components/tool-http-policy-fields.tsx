'use client'

import { useTranslation } from '@/context/i18n-provider'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

import type { Tr } from '../lib/format'

export interface ToolHTTPPolicyValue {
  tool_http_user_agent: string
  forbid_tool_insecure_tls: boolean
}

/** Printable ASCII, at most 256 characters (the API refuses anything else). */
export function toolUserAgentError(ua: string, tr?: Tr): string | null {
  if (ua.length > 256) return tr ? tr('sensors.httpPolicy.uaTooLong') : 'At most 256 characters.'
  if (/[^\x20-\x7e]/.test(ua))
    return tr ? tr('sensors.httpPolicy.uaNotAscii') : 'Use printable ASCII characters only.'
  return null
}

/**
 * The organization's layer of its scan tools' HTTP settings (api RFC-060
 * §4.1), sent with every scan job. It only narrows: a sensor's local policy
 * decides first, and the organization can never allow what it forbids.
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
  const uaError = toolUserAgentError(value.tool_http_user_agent, t)
  return (
    <div className="space-y-4" data-testid="tool-http-policy-fields">
      <div className="space-y-2">
        <Label htmlFor="tenant-tool-user-agent">{t('sensors.httpPolicy.ua.label')}</Label>
        <p className="text-sm text-muted-foreground" id="tenant-tool-user-agent-desc">
          {t('sensors.httpPolicy.ua.help')}
        </p>
        <Input
          id="tenant-tool-user-agent"
          aria-describedby="tenant-tool-user-agent-desc"
          aria-invalid={uaError ? true : undefined}
          placeholder="acme-security-scan (+soc@acme.example)"
          value={value.tool_http_user_agent}
          maxLength={256}
          onChange={(e) => onChange({ ...value, tool_http_user_agent: e.target.value })}
          disabled={disabled}
        />
        {uaError && <p className="text-sm text-destructive">{uaError}</p>}
      </div>
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
    </div>
  )
}
