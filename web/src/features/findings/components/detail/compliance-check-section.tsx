'use client'

/**
 * A configuration check result (a benchmark audit such as a CIS check):
 *
 *   result        PASSED / FAILED / WARNING / ERROR, as the audit reported it
 *   benchmark     name and version, profile, control number, audit file
 *   expected      the policy value, beside the actual value
 *   actual        the sub-checks, failed first, each opening to the file,
 *                 the expression it had to match and the lines it found;
 *                 the raw value when the audit wrote no sub-checks
 *   references    the control's mappings, grouped by framework
 *
 * Everything is producer-supplied text, rendered as text (UntrustedTextBlock
 * for multi-line values). The values come from complianceCheckOf.
 */

import * as React from 'react'
import { ChevronRight, ScrollText } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Tag } from '@/components/ui/tag'
import { ToneChip, type Tone } from '@/components/ui/tone-chip'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { UntrustedTextBlock } from '@/features/shared/components/untrusted-text-block'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import type {
  ComplianceCheck,
  ComplianceOutcome,
  ComplianceReferenceGroup,
  ComplianceSubCheck,
} from '../../lib/compliance-check'

const OUTCOME_TONE: Record<ComplianceOutcome, Tone> = {
  PASSED: 'ok',
  FAILED: 'danger',
  WARNING: 'caution',
  ERROR: 'neutral',
  SKIPPED: 'quiet',
}

const OUTCOME_LABEL: Record<ComplianceOutcome, string> = {
  PASSED: 'Passed',
  FAILED: 'Failed',
  WARNING: 'Warning',
  ERROR: 'Error',
  SKIPPED: 'Skipped',
}

/** Reference groups shown before "+N more", and ids per group. */
const GROUPS_SHOWN = 4
const IDS_SHOWN = 4

export function ComplianceOutcomeChip({ outcome }: { outcome: ComplianceOutcome }) {
  const { t } = useTranslation()
  return (
    <ToneChip
      tone={OUTCOME_TONE[outcome]}
      value={outcome}
      label={t(`findings.compliance.outcome.${outcome}`, OUTCOME_LABEL[outcome])}
    />
  )
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[13px] [overflow-wrap:anywhere]">{children}</span>
}

function SubCheckRow({ sc }: { sc: ComplianceSubCheck }) {
  const { t } = useTranslation()
  const hasDetail = !!(sc.file || sc.expect || sc.detail)
  const head = (
    <span className="flex min-w-0 items-start gap-2">
      <ComplianceOutcomeChip outcome={sc.outcome} />
      <span className="min-w-0 text-sm [overflow-wrap:anywhere]">
        {sc.name || t('findings.compliance.unnamedSubCheck', 'Unnamed sub-check')}
      </span>
    </span>
  )
  if (!hasDetail) {
    return <li className="px-3 py-2">{head}</li>
  }
  return (
    <li>
      <details className="group/sub" data-slot="compliance-sub-check" data-outcome={sc.outcome}>
        <summary className="flex cursor-pointer list-none items-start gap-1.5 px-3 py-2 select-none hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [&::-webkit-details-marker]:hidden">
          <ChevronRight
            className="mt-1 h-3 w-3 shrink-0 text-muted-foreground transition-transform group-open/sub:rotate-90"
            aria-hidden
          />
          {head}
        </summary>
        <div className="space-y-2 px-3 pb-3 ps-7">
          <DetailFieldGrid>
            <DetailField label={t('findings.compliance.file', 'File')} full>
              {sc.file ? <Mono>{sc.file}</Mono> : null}
            </DetailField>
            <DetailField label={t('findings.compliance.mustMatch', 'Must match')} full>
              {sc.expect ? <Mono>{sc.expect}</Mono> : null}
            </DetailField>
          </DetailFieldGrid>
          {sc.detail && (
            <UntrustedTextBlock
              text={sc.detail}
              label={t('findings.compliance.found', 'What the check found')}
              caption={t('findings.compliance.found', 'What the check found')}
              collapseLines={12}
            />
          )}
        </div>
      </details>
    </li>
  )
}

function SubChecks({ check }: { check: ComplianceCheck }) {
  const { t } = useTranslation()
  const failed = check.subChecks.filter((s) => s.outcome !== 'PASSED').length
  return (
    <div className="min-w-0 space-y-2">
      <p className="text-xs text-muted-foreground">
        {failed > 0
          ? t(
              'findings.compliance.subChecksFailed',
              '{failed} of {total} sub-checks did not pass',
              {
                failed,
                total: check.subChecks.length,
              }
            )
          : t('findings.compliance.subChecksPassed', 'All {total} sub-checks passed', {
              total: check.subChecks.length,
            })}
      </p>
      {check.preamble && (
        <p className="text-sm whitespace-pre-line [overflow-wrap:anywhere]">{check.preamble}</p>
      )}
      <ul
        className="divide-y rounded-md border"
        aria-label={t('findings.compliance.subChecks', 'Sub-checks')}
      >
        {check.subChecks.map((sc, i) => (
          <SubCheckRow key={i} sc={sc} />
        ))}
      </ul>
    </div>
  )
}

function ReferenceGroup({ group }: { group: ComplianceReferenceGroup }) {
  const { t } = useTranslation()
  const [all, setAll] = React.useState(false)
  const ids = all ? group.ids : group.ids.slice(0, IDS_SHOWN)
  const rest = group.ids.length - ids.length
  return (
    <li className="flex min-w-0 flex-wrap items-center gap-1.5">
      <span className="me-1 text-xs text-muted-foreground" title={group.framework}>
        {group.label}
      </span>
      {ids.map((id) => (
        <Tag key={id} label={id} className="font-mono" />
      ))}
      {group.ids.length === 0 && <Tag label={group.framework} />}
      {rest > 0 && (
        <button
          type="button"
          className="rounded-sm text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          onClick={() => setAll(true)}
        >
          {t('findings.compliance.moreIds', '+{count} more', { count: rest })}
        </button>
      )}
    </li>
  )
}

function References({ groups }: { groups: ComplianceReferenceGroup[] }) {
  const { t } = useTranslation()
  const [all, setAll] = React.useState(false)
  const shown = all ? groups : groups.slice(0, GROUPS_SHOWN)
  const rest = groups.length - shown.length
  return (
    <div className="min-w-0 space-y-1.5">
      <p className="text-body text-muted-foreground">
        {t('findings.compliance.references', 'Mapped controls')}
      </p>
      <ul className="space-y-1.5">
        {shown.map((g) => (
          <ReferenceGroup key={g.framework} group={g} />
        ))}
      </ul>
      {rest > 0 && (
        <button
          type="button"
          className="rounded-sm text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          onClick={() => setAll(true)}
        >
          {t('findings.compliance.moreFrameworks', '+{count} more frameworks', { count: rest })}
        </button>
      )}
    </div>
  )
}

export interface ComplianceCheckSectionProps {
  check: ComplianceCheck
  /** Narrow container (the drawer): expected and actual stack. */
  compact?: boolean
  className?: string
}

export function ComplianceCheckSection({ check, compact, className }: ComplianceCheckSectionProps) {
  const { t } = useTranslation()
  const benchmark = [check.benchmark, check.benchmarkVersion && `v${check.benchmarkVersion}`]
    .filter(Boolean)
    .join(' ')
  const expectedLabel = t('findings.compliance.expected', 'Expected (policy) value')
  const actualLabel = t('findings.compliance.actual', 'Actual value')
  return (
    <DetailSection
      title={t('findings.compliance.title', 'Configuration check')}
      icon={ScrollText}
      className={className}
      actions={check.outcome ? <ComplianceOutcomeChip outcome={check.outcome} /> : undefined}
    >
      <DetailFieldGrid>
        <DetailField label={t('findings.compliance.benchmark', 'Benchmark')}>
          {benchmark || null}
        </DetailField>
        <DetailField label={t('findings.compliance.profile', 'Profile')}>
          {check.profile}
        </DetailField>
        <DetailField label={t('findings.compliance.control', 'Control')}>
          {check.control ? <Mono>{check.control}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.compliance.auditFile', 'Audit file')}>
          {check.auditFile ? <Mono>{check.auditFile}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.compliance.error', 'Why the check did not run')} full>
          {check.error ? (
            <span className="[overflow-wrap:anywhere]">{toDisplayText(check.error, 500)}</span>
          ) : null}
        </DetailField>
      </DetailFieldGrid>

      {(check.policyValue || check.actualValue) && (
        <div
          className={cn('grid min-w-0 grid-cols-1 gap-4', !compact && 'lg:grid-cols-2')}
          data-slot="compliance-values"
        >
          <div className="min-w-0 space-y-1">
            <p className="text-body text-muted-foreground">{expectedLabel}</p>
            {check.policyValue ? (
              <UntrustedTextBlock
                text={check.policyValue}
                label={expectedLabel}
                collapseLines={12}
              />
            ) : (
              <p className="text-sm text-muted-foreground">
                {t('findings.compliance.notReported', 'Not reported by the scanner.')}
              </p>
            )}
          </div>
          <div className="min-w-0 space-y-1">
            <p className="text-body text-muted-foreground">{actualLabel}</p>
            {check.subChecks.length > 0 ? (
              <SubChecks check={check} />
            ) : check.actualValue ? (
              <UntrustedTextBlock text={check.actualValue} label={actualLabel} collapseLines={12} />
            ) : (
              <p className="text-sm text-muted-foreground">
                {t('findings.compliance.notReported', 'Not reported by the scanner.')}
              </p>
            )}
          </div>
        </div>
      )}

      {check.references.length > 0 && <References groups={check.references} />}
    </DetailSection>
  )
}
