'use client'

import { useMemo } from 'react'
import { HealthStatus } from '@/components/ui/health-status'
import { TextLink } from '@/components/ui/text-link'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsBlock, SettingsRow, SettingsSection } from '@/features/shared'
import { useSecurityOverview } from '../api/use-security-overview'
import { normalizeChecks, safeInternalLink } from '../lib/checks'

/**
 * "Needs attention" at the top of /settings for owners and administrators:
 * the security overview in brief. The score and the counts, then the first
 * things to fix (risks before warnings), each linking to its setting.
 * Renders nothing while loading, on an error or for anyone who cannot read
 * the overview (`enabled` false).
 */
export function SettingsAttention({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation()
  const { data } = useSecurityOverview(enabled)
  const todo = useMemo(
    () =>
      normalizeChecks(data?.checks ?? [])
        .filter((c) => c.status === 'risk' || c.status === 'warn')
        .sort((a, b) => (a.status === b.status ? 0 : a.status === 'risk' ? -1 : 1))
        .slice(0, 3),
    [data]
  )
  if (!enabled || !data) return null
  const score = data.score ?? 100
  const risks = data.counts?.risk ?? 0
  const warns = data.counts?.warn ?? 0

  return (
    <SettingsSection
      framed
      id="settings-attention"
      title={t('settings.attention.title', 'Needs attention')}
      description={
        <>
          <span
            aria-label={t('securityOverview.score.aria', 'Security score: {score} out of 100', {
              score,
            })}
          >
            {t('settings.attention.score', 'Security score {score} / 100', { score })}
          </span>
          {', '}
          {t(
            'settings.securityCard.counts',
            '{risks, plural, one {# risk} other {# risks}}, {warns, plural, one {# warning} other {# warnings}}',
            { risks, warns }
          )}
        </>
      }
      actions={
        <TextLink href="/settings/security" className="text-dense font-medium text-signal-text">
          {t('settings.securityCard.open', 'Open the security overview')}
        </TextLink>
      }
    >
      {todo.length === 0 ? (
        <SettingsBlock>
          <p className="text-body text-muted-foreground">
            {t('settings.securityCard.allGood', 'Nothing needs attention right now.')}
          </p>
        </SettingsBlock>
      ) : (
        todo.map((c) => {
          const href = safeInternalLink(c.link)
          const title = t(`securityOverview.check.${c.id}.title`, c.id)
          return (
            <SettingsRow
              key={c.id}
              label={
                <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                  <HealthStatus
                    state={c.status === 'risk' ? 'down' : 'warn'}
                    label={t(`securityOverview.status.${c.status}`, c.status)}
                  />
                  <span className="min-w-0 font-normal">{title}</span>
                </span>
              }
            >
              {href && (
                <TextLink
                  href={href}
                  className="text-dense font-medium text-signal-text"
                  aria-label={t('settings.attention.fixNamed', 'Open the setting: {name}', {
                    name: title,
                  })}
                >
                  {t('settings.attention.fix', 'Open the setting')}
                </TextLink>
              )}
            </SettingsRow>
          )
        })
      )}
    </SettingsSection>
  )
}
