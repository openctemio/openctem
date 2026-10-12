'use client'

import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

export interface ToolHTTPPolicyValue {
  tool_http_user_agent: string
  forbid_tool_insecure_tls: boolean
}

/** Printable ASCII, at most 256 characters (the API refuses anything else). */
export function toolUserAgentError(ua: string): string | null {
  if (ua.length > 256) return 'At most 256 characters.'
  if (/[^\x20-\x7e]/.test(ua)) return 'Use printable ASCII characters only.'
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
  const uaError = toolUserAgentError(value.tool_http_user_agent)
  return (
    <div className="space-y-4" data-testid="tool-http-policy-fields">
      <div className="space-y-2">
        <Label htmlFor="tenant-tool-user-agent">User-Agent of scan tools</Label>
        <p className="text-sm text-muted-foreground" id="tenant-tool-user-agent-desc">
          Sent by your scan tools instead of their own, so the owners of the scanned systems
          recognize your scans in their logs. A sensor whose local policy sets its own User-Agent
          keeps it. Empty: each tool sends its own.
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
          <Label htmlFor="tenant-tool-insecure-tls">
            Refuse tools that skip TLS certificate verification
          </Label>
          <p className="text-sm text-muted-foreground" id="tenant-tool-insecure-tls-desc">
            On: a scan tool configured to skip certificate verification toward its targets is
            refused on every sensor. Turning it off again is audited.
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
