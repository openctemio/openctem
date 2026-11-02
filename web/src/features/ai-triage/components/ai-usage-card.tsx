'use client'

import Link from '@/components/link'
import { Gauge } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'
import { Meter } from '@/features/shared/components/meter'

import type { AIConfig } from '../types/ai-triage.types'

/**
 * This month's AI use against the organization's limit, and where the other
 * limit on what reaches an AI lives (the highest TLP, in the MCP policy). The
 * monthly limit is set by the platform administrator; the organization reads
 * it here.
 */
export function AIUsageCard({ config }: { config?: AIConfig }) {
  const { t } = useTranslation()
  const limit = config?.monthlyTokenLimit ?? 0
  const used = config?.tokensUsedThisMonth ?? 0
  const spent = limit > 0 && used >= limit

  return (
    <Card id="ai-usage">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Gauge className="h-4 w-4" aria-hidden />
          {t('settings.ai.limits.title', 'Use and limits')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.ai.limits.description',
            'Tokens used by AI triage this month. The monthly limit is set by your platform administrator.'
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {limit > 0 ? (
          <div className="space-y-2">
            <p className="text-sm">
              {t('settings.ai.usage', 'This month: {used} of {limit} tokens used.', {
                used: used.toLocaleString(),
                limit: limit.toLocaleString(),
              })}
            </p>
            <Meter
              value={used}
              max={limit}
              tone={spent ? 'warning' : 'default'}
              label={t('settings.ai.limits.meter', '{used} of {limit} tokens used this month', {
                used: used.toLocaleString(),
                limit: limit.toLocaleString(),
              })}
            />
            {spent && (
              <p className="text-sm text-muted-foreground">
                {t(
                  'settings.ai.limits.spent',
                  'The limit is reached: new analyses wait until next month or until your platform administrator raises it.'
                )}
              </p>
            )}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            {t(
              'settings.ai.limits.noLimit',
              'This month: {used} tokens used. No monthly limit is set.',
              {
                used: used.toLocaleString(),
              }
            )}
          </p>
        )}

        <div className="flex flex-col gap-2 rounded-md border p-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <p className="text-sm font-medium">
              {t('settings.ai.limits.tlpTitle', 'Highest TLP sent to AI')}
            </p>
            <p className="text-sm text-muted-foreground">
              {t(
                'settings.ai.limits.tlpBody',
                'Pentest campaigns above this level are never sent to an AI. It is one policy for AI triage and AI assistants.'
              )}
            </p>
          </div>
          <Button asChild variant="outline" size="sm" className="shrink-0">
            <Link href="/settings/mcp?tab=policy">
              {t('settings.ai.limits.tlpLink', 'Open the policy')}
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
