'use client'

import { Scale } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection, UntrustedTextBlock } from '@/features/shared'

import { reasonLabel, versionMatchEvidence } from '../types'

interface VersionMatchPanelProps {
  metadata: Record<string, unknown> | undefined
}

/**
 * "Why this finding" for a finding the vulnerability matcher created
 * (RFC-066): the software version a scan saw, the advisory range it falls
 * in, and what lowered the confidence. Renders nothing for other findings.
 */
export function VersionMatchPanel({ metadata }: VersionMatchPanelProps) {
  const { t } = useTranslation()
  const ev = versionMatchEvidence(metadata)
  if (!ev) return null
  const likely = ev.label === 'likely'
  return (
    <DetailSection title={t('settings.vulnMatching.panel.title', 'Why this finding')} icon={Scale}>
      <div className="space-y-3 text-sm">
        <p>
          {t('settings.vulnMatching.panel.sawPrefix', 'A scan saw')}{' '}
          <span className="font-medium">
            {[ev.vendor, ev.product].filter(Boolean).join(' ')} {ev.version}
          </span>
          {ev.location
            ? t('settings.vulnMatching.panel.onLocation', ' on {location}', {
                location: ev.location,
              })
            : ''}
          {t(
            'settings.vulnMatching.panel.sawSuffix',
            ', and the advisory lists that version as affected. Nothing has exploited or probed it: the version alone is the evidence.'
          )}
        </p>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant={likely ? 'default' : 'outline'}>
            {likely
              ? t('assets.software.likely', 'Likely')
              : t('assets.software.potential', 'Potential')}
            {ev.confidence != null
              ? ` · ${t('assets.software.confidence', 'confidence {value}', { value: ev.confidence })}`
              : ''}
          </Badge>
          {ev.qualifier && (
            <Badge
              variant="outline"
              title={t(
                'assets.software.qualifierHint',
                'Distribution build: the vendor may have back-ported fixes'
              )}
            >
              {ev.qualifier}
            </Badge>
          )}
          {ev.source && (
            <Badge variant="secondary">
              {t('settings.vulnMatching.panel.source', 'Source: {name}', {
                name: ev.source.toUpperCase(),
              })}
            </Badge>
          )}
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
          <dt className="text-muted-foreground">
            {t('settings.vulnMatching.panel.range', 'Affected range')}
          </dt>
          <dd className="tabular-nums">
            {ev.range || t('assets.software.rangeNotStated', 'not stated')}
          </dd>
          <dt className="text-muted-foreground">
            {t('settings.vulnMatching.panel.observed', 'Observed version')}
          </dt>
          <dd className="tabular-nums">
            {ev.version || t('settings.vulnMatching.panel.unknown', 'unknown')}
          </dd>
        </dl>
        {(ev.reasons ?? []).length > 0 && (
          <div>
            <p className="text-muted-foreground">
              {t('settings.vulnMatching.panel.lowered', 'Confidence lowered because:')}
            </p>
            <ul className="list-disc pl-5">
              {(ev.reasons ?? []).map((r) => (
                <li key={r}>{t(`assets.software.reason.${r}`, reasonLabel(r))}</li>
              ))}
            </ul>
          </div>
        )}
        {ev.evidence && (
          <UntrustedTextBlock
            label={t('settings.vulnMatching.panel.reported', 'What the scan reported')}
            text={ev.evidence}
          />
        )}
        <p className="text-xs text-muted-foreground">
          {t(
            'settings.vulnMatching.panel.footer',
            'Upgrading out of the range resolves this finding on the next scan; a scanner or a validation that confirms it replaces this evidence.'
          )}
        </p>
      </div>
    </DetailSection>
  )
}
