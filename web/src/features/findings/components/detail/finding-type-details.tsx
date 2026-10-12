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
  return <span className="font-mono text-[13px] break-all">{children}</span>
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
  const c = finding.component
  const name = c?.name || meta(finding, 'package_name', 'component_name')
  if (!name) return null
  const version = c?.version || meta(finding, 'installed_version', 'current_version')
  const fixed = finding.advisory?.fixedVersions ?? []
  const dep =
    c?.dependencyType === 'direct'
      ? 'Direct'
      : c?.dependencyType === 'transitive'
        ? 'Transitive'
        : c?.dependencyType
  return (
    <DetailSection title="Affected package" icon={Package}>
      <DetailFieldGrid>
        <DetailField label="Package">
          <Mono>
            {name}
            {version && `@${version}`}
          </Mono>
        </DetailField>
        <DetailField label="Fixed in">
          {fixed.length > 0 ? (
            <Mono>{fixed.join(', ')}</Mono>
          ) : c?.fixedIn ? (
            <Mono>{c.fixedIn}</Mono>
          ) : null}
        </DetailField>
        <DetailField label="Ecosystem">{c?.ecosystem || meta(finding, 'ecosystem')}</DetailField>
        <DetailField label="Dependency">
          {dep ? [dep, c?.manifestFile && `via ${c.manifestFile}`].filter(Boolean).join(' ') : null}
        </DetailField>
        <DetailField label="License">{c?.license}</DetailField>
        <DetailField label="Package URL" full>
          {c?.purl || meta(finding, 'purl') ? (
            <Mono>{c?.purl || meta(finding, 'purl')}</Mono>
          ) : null}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function SecretSection({ finding }: { finding: FindingDetail }) {
  const s = finding.secretDetails
  if (!s) return null
  const active = s.valid === true && s.revoked !== true
  const state = s.revoked
    ? 'Revoked'
    : s.valid === true
      ? 'Active'
      : s.valid === false
        ? 'Invalid'
        : 'Not verified'
  return (
    <DetailSection title="Exposed credential" icon={KeyRound}>
      <DetailFieldGrid>
        <DetailField label="Type">{s.secretType?.replace(/_/g, ' ')}</DetailField>
        <DetailField label="Service">{s.service}</DetailField>
        <DetailField label="Validity">
          <span
            className={cn(active && 'font-medium text-destructive', s.revoked && 'text-success')}
          >
            {state}
          </span>
          {s.verifiedAt && (
            <span className="text-muted-foreground"> · checked {formatDate(s.verifiedAt)}</span>
          )}
        </DetailField>
        <DetailField label="Value">
          {s.maskedValue ? <Mono>{s.maskedValue}</Mono> : null}
        </DetailField>
        <DetailField label="Age">{s.ageInDays != null ? `${s.ageInDays} days` : null}</DetailField>
        <DetailField label="In history">
          {s.commitCount
            ? `${s.commitCount} commit${s.commitCount === 1 ? '' : 's'}${s.inHistoryOnly ? ' (history only)' : ''}`
            : s.inHistoryOnly
              ? 'History only'
              : null}
        </DetailField>
        <DetailField label="Expires">{formatDate(s.expiresAt)}</DetailField>
        <DetailField label="Rotation due">{formatDate(s.rotationDueAt)}</DetailField>
        <DetailField label="Scopes" full>
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
  const m = finding.misconfigDetails
  if (!m) return null
  return (
    <DetailSection title="Misconfigured resource" icon={Settings2}>
      <DetailFieldGrid>
        <DetailField label="Resource">
          {m.resourceType || m.resourceName ? (
            <Mono>{[m.resourceType, m.resourceName].filter(Boolean).join('.')}</Mono>
          ) : null}
        </DetailField>
        <DetailField label="Policy">
          {m.policyId || m.policyName ? (
            <span>
              {m.policyId && <Mono>{m.policyId}</Mono>}
              {m.policyId && m.policyName && ' · '}
              {m.policyName}
            </span>
          ) : null}
        </DetailField>
        <DetailField label="File" full>
          {m.resourcePath ? <Mono>{m.resourcePath}</Mono> : null}
        </DetailField>
        <DetailField label="Cause" full>
          {m.cause}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function WebRequestSection({ finding }: { finding: FindingDetail }) {
  const endpoint = meta(finding, 'endpoint', 'url', 'matched_at')
  const method = meta(finding, 'method', 'http_method').toUpperCase()
  const param = meta(finding, 'parameter', 'param')
  const request = meta(finding, 'request', 'http_request')
  const response = meta(finding, 'response', 'http_response')
  if (!endpoint && !request && !response) return null
  return (
    <DetailSection title="Affected endpoint" icon={Globe}>
      <DetailFieldGrid>
        <DetailField label="Endpoint" full>
          {endpoint ? (
            <Mono>
              {method && <span className="me-1.5 font-semibold">{method}</span>}
              {endpoint}
            </Mono>
          ) : null}
        </DetailField>
        <DetailField label="Parameter">{param ? <Mono>{param}</Mono> : null}</DetailField>
      </DetailFieldGrid>
      {(request || response) && (
        <DetailDisclosure summary="Request and response">
          <div className="mt-2 grid gap-2 lg:grid-cols-2">
            {[
              ['Request', request],
              ['Response', response],
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
  const c = finding.complianceDetails
  if (!c) return null
  return (
    <DetailSection title="Compliance control" icon={ScrollText}>
      <DetailFieldGrid>
        <DetailField label="Framework">
          {c.framework
            ? `${c.framework.toUpperCase()}${c.frameworkVersion ? ` v${c.frameworkVersion}` : ''}`
            : null}
        </DetailField>
        <DetailField label="Result">
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
        <DetailField label="Control">
          {c.controlId || c.controlName ? (
            <span>
              {c.controlId && <Mono>{c.controlId}</Mono>}
              {c.controlId && c.controlName && ' · '}
              {c.controlName}
            </span>
          ) : null}
        </DetailField>
        <DetailField label="Section">{c.section}</DetailField>
        <DetailField label="Requirement" full>
          {c.controlDescription}
        </DetailField>
      </DetailFieldGrid>
    </DetailSection>
  )
}

function Web3Section({ finding }: { finding: FindingDetail }) {
  const w = finding.web3Details
  if (!w) return null
  return (
    <DetailSection title="Smart contract" icon={Wallet}>
      <DetailFieldGrid>
        <DetailField label="Chain">
          {w.chain ? `${w.chain}${w.chainId != null ? ` (ID ${w.chainId})` : ''}` : null}
        </DetailField>
        <DetailField label="SWC">{w.swcId ? <Mono>{w.swcId}</Mono> : null}</DetailField>
        <DetailField label="Contract" full>
          {w.contractAddress ? <Mono>{w.contractAddress}</Mono> : null}
        </DetailField>
        <DetailField label="Function">
          {w.functionSignature ? <Mono>{w.functionSignature}</Mono> : null}
        </DetailField>
        <DetailField label="Selector">
          {w.functionSelector ? <Mono>{w.functionSelector}</Mono> : null}
        </DetailField>
        <DetailField label="Transaction" full>
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
