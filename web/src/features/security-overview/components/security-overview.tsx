'use client'

/**
 * Settings › Security overview: one score and a short checklist of what to fix
 * first (sign-in, people, credentials, scanning, organization). The API
 * computes statuses; this component renders the wording from the dictionaries
 * by check id, so every language reads the same overview.
 *
 * Settings page frame (web/docs/ui-style-contract.md, "Settings pages"): the
 * score first, then one section per group with the checks that need a look,
 * and the passed checks folded at the end (shown on demand).
 */

import { useId, useMemo, useState } from 'react'
import { RefreshCw } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { HealthStatus } from '@/components/ui/health-status'
import { TextLink } from '@/components/ui/text-link'
import { useTranslation } from '@/context/i18n-provider'
import { MetricStrip, SettingsPage, SettingsRow, SettingsSection } from '@/features/shared'
import { formatRelative } from '@/lib/format-date'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

import { useSecurityOverview } from '../api/use-security-overview'
import {
  groupChecks,
  normalizeChecks,
  safeInternalLink,
  type CheckStatus,
  type OverviewCheck,
} from '../lib/checks'

/** The shared state chip of each check status (state words, not colour only). */
const STATUS_HEALTH = {
  risk: 'down',
  warn: 'warn',
  pass: 'ok',
  info: 'unknown',
} as const satisfies Record<CheckStatus, string>

function CheckRow({ check }: { check: OverviewCheck }) {
  const { t } = useTranslation()
  const link = check.status === 'pass' ? null : safeInternalHref(safeInternalLink(check.link))
  const base = `securityOverview.check.${check.id}`
  const title = t(`${base}.title`, check.id)
  const desc = t(`${base}.desc.${check.status}`, '', { count: check.count ?? 0 })
  return (
    <SettingsRow
      id={`check-${check.id}`}
      label={
        <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
          <HealthStatus
            state={STATUS_HEALTH[check.status]}
            label={t(`securityOverview.status.${check.status}`, check.status)}
          />
          <span className="min-w-0">{title}</span>
        </span>
      }
      hint={desc || undefined}
    >
      {link && (
        <TextLink
          href={link}
          className="text-dense font-medium text-signal-text"
          aria-label={t('securityOverview.reviewNamed', 'Review: {name}', { name: title })}
        >
          {check.count && check.count > 0
            ? t('securityOverview.reviewCount', 'Review {count}', { count: check.count })
            : t('securityOverview.review', 'Review')}
        </TextLink>
      )}
    </SettingsRow>
  )
}

export function SecurityOverview() {
  const { t, locale } = useTranslation()
  const { data, error, isLoading, isValidating, mutate } = useSecurityOverview()
  const [showPassed, setShowPassed] = useState(false)
  const passedListId = useId()

  const { open, passed } = useMemo(() => {
    const checks = normalizeChecks(data?.checks ?? [])
    return {
      open: groupChecks(checks.filter((c) => c.status !== 'pass')),
      passed: checks.filter((c) => c.status === 'pass'),
    }
  }, [data])

  const title = t('securityOverview.title', 'Security overview')
  const description = t(
    'securityOverview.description',
    'How well this organization is protected, and what to fix first.'
  )
  const recheck = (
    <Button
      variant="outline"
      onClick={() => void mutate()}
      disabled={isLoading || isValidating}
      aria-busy={isValidating}
    >
      <RefreshCw className={cn(isValidating && 'animate-spin')} aria-hidden="true" />
      {t('securityOverview.recheck', 'Re-check')}
    </Button>
  )

  if (isLoading || error || !data) {
    return (
      <SettingsPage
        title={title}
        description={description}
        actions={recheck}
        state={isLoading ? 'loading' : 'error'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }

  const score = Math.max(0, Math.min(100, Math.round(data.score ?? 0)))
  const counts = data.counts ?? {}
  const checked = formatRelative(data.generated_at, '', locale)

  return (
    <SettingsPage title={title} description={description} actions={recheck}>
      <section
        id="security-score"
        aria-label={t('securityOverview.score.title', 'Security score')}
        className="space-y-2"
      >
        {checked && (
          <p className="text-dense text-muted-foreground">
            {t('securityOverview.checkedAgo', 'Checked {when}', { when: checked })}
          </p>
        )}
        <MetricStrip
          items={[
            {
              key: 'score',
              label: t('securityOverview.score.title', 'Security score'),
              value: <span data-testid="security-score">{score}</span>,
              hint: t('securityOverview.score.outOf', '/ 100'),
              description: t('securityOverview.score.aria', 'Security score: {score} out of 100', {
                score,
              }),
            },
            {
              key: 'risk',
              label: t('securityOverview.counts.risk', 'Checks at risk'),
              value: <span data-testid="count-risk">{counts.risk ?? 0}</span>,
              tone: (counts.risk ?? 0) > 0 ? 'danger' : 'default',
            },
            {
              key: 'warn',
              label: t('securityOverview.counts.warn', 'Checks with a warning'),
              value: <span data-testid="count-warn">{counts.warn ?? 0}</span>,
              tone: (counts.warn ?? 0) > 0 ? 'warning' : 'default',
            },
            {
              key: 'pass',
              label: t('securityOverview.counts.pass', 'Checks passed'),
              value: <span data-testid="count-pass">{counts.pass ?? 0}</span>,
            },
          ]}
        />
      </section>

      {open.map(([group, checks]) => (
        <SettingsSection
          key={group}
          framed
          id={`security-group-${group}`}
          title={t(`securityOverview.group.${group}`, group)}
        >
          {checks.map((c) => (
            <CheckRow key={c.id} check={c} />
          ))}
        </SettingsSection>
      ))}

      {passed.length > 0 && (
        <SettingsSection
          framed
          id="security-passed"
          title={t('securityOverview.passed.title', 'Passed checks')}
          description={t('securityOverview.passed.description', 'Nothing to do here.')}
          actions={
            <Button
              variant="ghost"
              aria-expanded={showPassed}
              aria-controls={passedListId}
              onClick={() => setShowPassed((v) => !v)}
            >
              {showPassed
                ? t(
                    'securityOverview.passed.hide',
                    '{count, plural, one {Hide the passed check} other {Hide the # passed checks}}',
                    { count: passed.length }
                  )
                : t(
                    'securityOverview.passed.show',
                    '{count, plural, one {Show the passed check} other {Show the # passed checks}}',
                    { count: passed.length }
                  )}
            </Button>
          }
        >
          <div id={passedListId} hidden={!showPassed}>
            {showPassed && passed.map((c) => <CheckRow key={c.id} check={c} />)}
          </div>
        </SettingsSection>
      )}
    </SettingsPage>
  )
}
