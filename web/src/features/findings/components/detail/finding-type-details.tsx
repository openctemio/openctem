'use client'

/**
 * The facts that differ by finding type, each as a plain section of
 * label → value fields: the package for a dependency finding, the credential
 * for a secret, the resource for a misconfiguration, the request for a web
 * finding, the control for a compliance check, the contract for web3.
 *
 * Replaces the coloured per-source banners that sat between the header and
 * the tabs: one look for every type, theme tokens only, nothing rendered for
 * a type the finding is not.
 */

import { Globe, KeyRound, Package, ScrollText, Settings2, Wallet } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import {
  DetailDisclosure,
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { cn } from '@/lib/utils'
import type { FindingDetail } from '../../types'

function meta(f: FindingDetail, ...keys: string[]): string {
  for (const k of keys) {
    const v = f.metadata?.[k]
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return ''
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-body break-all">{children}</span>
}

function formatDate(iso?: string) {
  if (!iso) return undefined
  const d = new Date(iso)
  return isNaN(d.getTime())
    ? undefined
    : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

// ---------------------------------------------------------------------------

function PackageSection({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const c = finding.component
  const name = c?.name || meta(finding, 'package_name', 'component_name')
  if (!name) return null
  const version = c?.version || meta(finding, 'installed_version', 'current_version')
  const fixed = finding.advisory?.fixedVersions ?? []
  const dep =
    c?.dependencyType === 'direct'
      ? t('findings.typeDetails.direct', 'Direct')
      : c?.dependencyType === 'transitive'
        ? t('findings.typeDetails.transitive', 'Transitive')
        : c?.dependencyType
  return (
    <DetailSection
      title={t('findings.typeDetails.affectedPackage', 'Affected package')}
      icon={Package}
    >
      <DetailFieldGrid>
        <DetailField label={t('findings.typeDetails.package', 'Package')}>
          <Mono>
            {name}
            {version && `@${version}`}
          </Mono>
        </DetailField>
        <DetailField label={t('findings.typeDetails.fixedIn', 'Fixed in')}>
          {fixed.length > 0 ? (
            <Mono>{fixed.join(', ')}</Mono>
          ) : c?.fixedIn ? (
            <Mono>{c.fixedIn}</Mono>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.ecosystem', 'Ecosystem')}>
          {c?.ecosystem || meta(finding, 'ecosystem')}
        </DetailField>
        <DetailField label={t('findings.typeDetails.dependency', 'Dependency')}>
          {dep
            ? [
                dep,
                c?.manifestFile &&
                  t('findings.typeDetails.via', 'via {file}', { file: c.manifestFile }),
              ]
                .filter(Boolean)
                .join(' ')
            : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.license', 'License')}>{c?.license}</DetailField>
        <DetailField label={t('findings.typeDetails.purl', 'Package URL')} full>
          {c?.purl || meta(finding, 'purl') ? (
            <Mono>{c?.purl || meta(finding, 'purl')}</Mono>
          ) : null}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function SecretSection({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const s = finding.secretDetails
  if (!s) return null
  const active = s.valid === true && s.revoked !== true
  const state = s.revoked
    ? t('findings.typeDetails.revoked', 'Revoked')
    : s.valid === true
      ? t('findings.typeDetails.active', 'Active')
      : s.valid === false
        ? t('findings.typeDetails.invalid', 'Invalid')
        : t('findings.typeDetails.notVerified', 'Not verified')
  return (
    <DetailSection
      title={t('findings.typeDetails.exposedCredential', 'Exposed credential')}
      icon={KeyRound}
    >
      <DetailFieldGrid>
        <DetailField label={t('findings.typeDetails.type', 'Type')}>
          {s.secretType?.replace(/_/g, ' ')}
        </DetailField>
        <DetailField label={t('findings.typeDetails.service', 'Service')}>{s.service}</DetailField>
        <DetailField label={t('findings.typeDetails.validity', 'Validity')}>
          <span
            className={cn(active && 'font-medium text-destructive', s.revoked && 'text-success')}
          >
            {state}
          </span>
          {s.verifiedAt && (
            <span className="text-muted-foreground">
              {' · '}
              {t('findings.typeDetails.checked', 'checked {date}', {
                date: formatDate(s.verifiedAt) ?? '',
              })}
            </span>
          )}
        </DetailField>
        <DetailField label={t('findings.typeDetails.value', 'Value')}>
          {s.maskedValue ? <Mono>{s.maskedValue}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.age', 'Age')}>
          {s.ageInDays != null
            ? t('findings.typeDetails.days', '{count} days', { count: s.ageInDays })
            : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.inHistory', 'In history')}>
          {s.commitCount
            ? (() => {
                const text =
                  s.commitCount === 1
                    ? t('findings.typeDetails.commit1', '{count} commit', { count: s.commitCount })
                    : t('findings.typeDetails.commitN', '{count} commits', { count: s.commitCount })
                return s.inHistoryOnly
                  ? t('findings.typeDetails.historyOnlyParen', '{text} (history only)', { text })
                  : text
              })()
            : s.inHistoryOnly
              ? t('findings.typeDetails.historyOnly', 'History only')
              : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.expires', 'Expires')}>
          {formatDate(s.expiresAt)}
        </DetailField>
        <DetailField label={t('findings.typeDetails.rotationDue', 'Rotation due')}>
          {formatDate(s.rotationDueAt)}
        </DetailField>
        <DetailField label={t('findings.typeDetails.scopes', 'Scopes')} full>
          {s.scopes && s.scopes.length > 0 ? (
            <span className="flex flex-wrap gap-1">
              {s.scopes.map((x) => (
                <Badge key={x} variant="outline" className="font-mono text-xs">
                  {x}
                </Badge>
              ))}
            </span>
          ) : null}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function MisconfigSection({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const m = finding.misconfigDetails
  if (!m) return null
  return (
    <DetailSection
      title={t('findings.typeDetails.misconfigured', 'Misconfigured resource')}
      icon={Settings2}
    >
      <DetailFieldGrid>
        <DetailField label={t('findings.typeDetails.resource', 'Resource')}>
          {m.resourceType || m.resourceName ? (
            <Mono>{[m.resourceType, m.resourceName].filter(Boolean).join('.')}</Mono>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.policy', 'Policy')}>
          {m.policyId || m.policyName ? (
            <span>
              {m.policyId && <Mono>{m.policyId}</Mono>}
              {m.policyId && m.policyName && ' · '}
              {m.policyName}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.file', 'File')} full>
          {m.resourcePath ? <Mono>{m.resourcePath}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.cause', 'Cause')} full>
          {m.cause}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function WebRequestSection({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const endpoint = meta(finding, 'endpoint', 'url', 'matched_at')
  const method = meta(finding, 'method', 'http_method').toUpperCase()
  const param = meta(finding, 'parameter', 'param')
  const request = meta(finding, 'request', 'http_request')
  const response = meta(finding, 'response', 'http_response')
  if (!endpoint && !request && !response) return null
  return (
    <DetailSection
      title={t('findings.typeDetails.affectedEndpoint', 'Affected endpoint')}
      icon={Globe}
    >
      <DetailFieldGrid>
        <DetailField label={t('findings.typeDetails.endpoint', 'Endpoint')} full>
          {endpoint ? (
            <Mono>
              {method && <span className="me-1.5 font-semibold">{method}</span>}
              {endpoint}
            </Mono>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.parameter', 'Parameter')}>
          {param ? <Mono>{param}</Mono> : null}
        </DetailField>
      </DetailFieldGrid>
      {(request || response) && (
        <DetailDisclosure summary={t('findings.typeDetails.reqResp', 'Request and response')}>
          <div className="mt-2 grid gap-2 lg:grid-cols-2">
            {[
              [t('findings.typeDetails.request', 'Request'), request],
              [t('findings.typeDetails.response', 'Response'), response],
            ]
              .filter(([, v]) => v)
              .map(([label, v]) => (
                <div key={label} className="min-w-0">
                  <div className="mb-1 text-xs text-muted-foreground">{label}</div>
                  <pre className="max-h-72 overflow-auto rounded-md border bg-muted/50 p-2.5 font-mono text-xs whitespace-pre-wrap">
                    {v}
                  </pre>
                </div>
              ))}
          </div>
        </DetailDisclosure>
      )}
    </DetailSection>
  )
}

function ComplianceSection({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const c = finding.complianceDetails
  if (!c) return null
  return (
    <DetailSection
      title={t('findings.typeDetails.complianceControl', 'Compliance control')}
      icon={ScrollText}
    >
      <DetailFieldGrid>
        <DetailField label={t('findings.typeDetails.framework', 'Framework')}>
          {c.framework
            ? `${c.framework.toUpperCase()}${c.frameworkVersion ? ` v${c.frameworkVersion}` : ''}`
            : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.result', 'Result')}>
          {c.result ? (
            <span
              className={cn(
                c.result === 'fail' && 'font-medium text-destructive',
                c.result === 'pass' && 'text-success'
              )}
            >
              {c.result.replace(/_/g, ' ')}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.control', 'Control')}>
          {c.controlId || c.controlName ? (
            <span>
              {c.controlId && <Mono>{c.controlId}</Mono>}
              {c.controlId && c.controlName && ' · '}
              {c.controlName}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.section', 'Section')}>{c.section}</DetailField>
        <DetailField label={t('findings.typeDetails.requirement', 'Requirement')} full>
          {c.controlDescription}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function Web3Section({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation()
  const w = finding.web3Details
  if (!w) return null
  return (
    <DetailSection title={t('findings.typeDetails.smartContract', 'Smart contract')} icon={Wallet}>
      <DetailFieldGrid>
        <DetailField label={t('findings.typeDetails.chain', 'Chain')}>
          {w.chain
            ? w.chainId != null
              ? t('findings.typeDetails.chainId', '{chain} (ID {id})', {
                  chain: w.chain,
                  id: w.chainId,
                })
              : w.chain
            : null}
        </DetailField>
        <DetailField label="SWC">{w.swcId ? <Mono>{w.swcId}</Mono> : null}</DetailField>
        <DetailField label={t('findings.typeDetails.contract', 'Contract')} full>
          {w.contractAddress ? <Mono>{w.contractAddress}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.function', 'Function')}>
          {w.functionSignature ? <Mono>{w.functionSignature}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.selector', 'Selector')}>
          {w.functionSelector ? <Mono>{w.functionSelector}</Mono> : null}
        </DetailField>
        <DetailField label={t('findings.typeDetails.transaction', 'Transaction')} full>
          {w.txHash ? <Mono>{w.txHash}</Mono> : null}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

/**
 * The type-specific sections that apply to this finding, in a stable order.
 * Returns an array so the caller can drop them into its own <DetailSections>.
 */
export function findingTypeSections(finding: FindingDetail): React.ReactNode[] {
  return [
    <PackageSection key="package" finding={finding} />,
    <SecretSection key="secret" finding={finding} />,
    <MisconfigSection key="misconfig" finding={finding} />,
    <WebRequestSection key="web" finding={finding} />,
    <ComplianceSection key="compliance" finding={finding} />,
    <Web3Section key="web3" finding={finding} />,
  ]
}

/** True when `findingTypeSections` has anything to show (for counts / layout). */
export function hasTypeDetails(f: FindingDetail): boolean {
  return !!(
    f.component ||
    f.metadata?.package_name ||
    f.secretDetails ||
    f.misconfigDetails ||
    f.complianceDetails ||
    f.web3Details ||
    f.metadata?.endpoint ||
    f.metadata?.url ||
    f.metadata?.request
  )
}
