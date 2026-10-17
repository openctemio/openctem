'use client'

import { AlertTriangle, CircleCheck, CircleOff } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { useProfileLabels } from '@/features/pentest/lib/use-pentest-labels'

import type { McpPolicy } from '../api/connections'
import { effectiveScopes } from './mcp-policy-card'

/** The policy at a glance, under the page header. */
export function McpStatusStrip({ policy }: { policy: McpPolicy }) {
  const { t } = useTranslation()
  const { tlpLabel } = useProfileLabels()
  const scopes = effectiveScopes(policy)
  const writes = policy.available_scopes.some((s) => s.write && scopes.includes(s.scope))

  if (!policy.enabled) {
    return (
      <div
        className="flex flex-wrap items-center gap-2"
        aria-label={t('mcp.status.label', 'Status')}
      >
        <Badge variant="destructive" className="gap-1">
          <CircleOff className="h-3.5 w-3.5" aria-hidden />
          {t('mcp.status.off', 'Off')}
        </Badge>
        <span className="text-muted-foreground text-xs">
          {t('mcp.status.offHint', 'No AI application or API key can use the MCP server.')}
        </span>
      </div>
    )
  }

  return (
    <ul className="flex flex-wrap items-center gap-2" aria-label={t('mcp.status.label', 'Status')}>
      <li>
        <Badge variant="secondary" className="gap-1">
          <CircleCheck className="text-success h-3.5 w-3.5" aria-hidden />
          {t('mcp.status.on', 'On')}
        </Badge>
      </li>
      <li>
        {policy.any_client ? (
          <Badge variant="destructive" className="gap-1">
            <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
            {t('mcp.status.anyClient', 'Unverified applications allowed')}
          </Badge>
        ) : (
          <Badge variant="outline">
            {t('mcp.status.verifiedOnly', 'Approved applications only')}
          </Badge>
        )}
      </li>
      <li>
        <Badge variant="outline">
          {writes
            ? t('mcp.status.canComment', 'Read and comment')
            : t('mcp.status.readOnly', 'Read-only')}
        </Badge>
      </li>
      <li>
        <Badge variant="outline">
          {t('mcp.status.days', 'Connections last {days} days', {
            days: policy.effective_refresh_days,
          })}
        </Badge>
      </li>
      <li>
        <Badge variant="outline">
          {t('mcp.status.tlp', 'Up to {tlp}', { tlp: tlpLabel(policy.max_tlp) })}
        </Badge>
      </li>
    </ul>
  )
}
