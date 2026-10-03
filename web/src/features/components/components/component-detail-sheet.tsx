/**
 * Component Detail Sheet
 *
 * Detail drawer for a software component, on the shared detail-drawer frame
 * (sensor drawer layout): name and version in the header, risk and reach as
 * stats, three tabs (Overview / CVEs / Assets).
 */

'use client'

import { formatEpssScore } from '@/lib/epss'
import * as React from 'react'
import { useRouter } from 'next/navigation'
import {
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  GitBranch,
  Globe,
  Hash,
  Layers,
  Package,
  Scale,
  Server,
  Zap,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { TabsCount } from '@/components/ui/tabs'
import { TooltipProvider } from '@/components/ui/tooltip'
import { copyToClipboard } from '@/lib/clipboard'
import { cn, sanitizeExternalUrl } from '@/lib/utils'
import { CRITICALITY_BADGE_SOFT } from '@/lib/criticality-colors'
import { toast } from 'sonner'
import { EcosystemBadge } from './ecosystem-badge'
import { SeverityBadge } from './severity-badge'
import { LicenseRiskBadge, LicenseCategoryBadge } from './license-badge'
import {
  DetailField,
  DetailFieldGrid,
  DetailHeader,
  DetailSection,
  DetailSections,
  DetailSheet,
  DetailStat,
  DetailStatGrid,
  DetailTabs,
  EmptyState,
  ErrorState,
  SheetPaginationFooter as PaginationFooter,
  type DetailMenuItem,
  type DetailTab,
} from '@/features/shared'
import type { Component } from '../types'
import { useComponentAssetsApi, useComponentVulnsApi } from '../api/use-components-api'
import { VulnerabilityDetailSheet } from '@/features/vulnerabilities'
import type { Vulnerability } from '@/features/vulnerabilities'
import type { Severity } from '@/features/shared/types'
import type { ApiComponentVulnerability } from '../api/component-api.types'

// ============================================
// Types
// ============================================

interface ComponentDetailSheetProps {
  /** The component to display (null when sheet is closed) */
  component: Component | null

  /** Whether the sheet is open */
  open: boolean

  /** Callback when open state changes */
  onOpenChange: (open: boolean) => void
}

// ============================================
// Helper Components
// ============================================

/**
 * Build a partial Vulnerability object from a row in the component-vulns API.
 * Used as `fallback` for VulnerabilityDetailSheet so its header renders
 * immediately while the full /vulnerabilities/{id} fetch is in flight.
 */
function vulnFallbackFromRow(v: ApiComponentVulnerability): Vulnerability {
  return {
    id: v.vulnerability_id,
    cve_id: v.cve_id,
    title: v.title,
    severity: v.severity as Severity,
    cvss_score: v.cvss_score ?? undefined,
    epss_score: v.epss_score ?? undefined,
    exploit_available: v.exploit_available,
    exploit_maturity: (v.exploit_maturity ?? 'none') as Vulnerability['exploit_maturity'],
    fixed_versions: v.fixed_versions,
    status: 'open',
    risk_score: 0,
    created_at: v.first_detected_at,
    updated_at: v.last_seen_at,
  }
}

// ============================================
// Component
// ============================================

const CRITICALITY_BADGE: Record<string, string> = CRITICALITY_BADGE_SOFT

const VULNS_PER_PAGE = 10
const ASSETS_PER_PAGE = 10

type Tab = 'overview' | 'vulnerabilities' | 'assets'

function riskTone(score: number) {
  return score >= 70 ? 'destructive' : score >= 40 ? 'warning' : 'default'
}

function TabLoading() {
  return (
    <div className="space-y-2" aria-hidden>
      {Array.from({ length: 3 }).map((_, i) => (
        <Skeleton key={i} className="h-16 w-full" />
      ))}
    </div>
  )
}

export function ComponentDetailSheet({ component, open, onOpenChange }: ComponentDetailSheetProps) {
  const router = useRouter()
  const [activeTab, setActiveTab] = React.useState<Tab>('overview')
  const [vulnsPage, setVulnsPage] = React.useState(1)
  const [assetsPage, setAssetsPage] = React.useState(1)
  // Selected CVE for the nested vulnerability detail sheet (cross-link).
  // We carry both id + a fallback Vulnerability object built from the row data
  // so the nested sheet's header renders instantly while the full detail loads.
  const [selectedVuln, setSelectedVuln] = React.useState<{
    id: string
    fallback: Vulnerability
  } | null>(null)

  // Vulnerabilities and Assets are both fetched as soon as the sheet opens
  // (page 1 only). The `total` from each response feeds the Overview tab
  // counts, and the data is reused when user clicks into the tab.
  // Subsequent page changes refetch via SWR key change.
  const componentId = open ? (component?.id ?? null) : null
  const {
    data: vulnsData,
    isLoading: vulnsLoading,
    error: vulnsError,
  } = useComponentVulnsApi(componentId, {
    page: vulnsPage,
    perPage: VULNS_PER_PAGE,
  })
  const {
    data: assetsData,
    isLoading: assetsLoading,
    error: assetsError,
  } = useComponentAssetsApi(componentId, assetsPage, ASSETS_PER_PAGE)

  // Reset tab + pagination when component changes
  React.useEffect(() => {
    if (component) {
      setActiveTab('overview')
      setVulnsPage(1)
      setAssetsPage(1)
    }
  }, [component])

  if (!component) return null

  const distinctCveCount = vulnsData?.total ?? 0
  const usedByAssetsCount = assetsData?.total ?? 0
  // Row 0 is the most concerning CVE: the backend orders by severity, then
  // KEV, then CVSS. Counting `data` would only count the current page.
  const worst = vulnsData?.data?.[0]

  const copy = (value: string, what: string) => {
    copyToClipboard(value)
    toast.success(`${what} copied to clipboard`)
  }

  const tabs: DetailTab<Tab>[] = [
    { value: 'overview', label: 'Overview' },
    {
      value: 'vulnerabilities',
      label: (
        <>
          CVEs
          {distinctCveCount > 0 && <TabsCount value={distinctCveCount} tone="danger" />}
        </>
      ),
    },
    {
      value: 'assets',
      label: (
        <>
          Assets
          {usedByAssetsCount > 0 && <TabsCount value={usedByAssetsCount} />}
        </>
      ),
    },
  ]

  const menu: DetailMenuItem[] = [
    { label: 'Copy PURL', icon: Copy, onSelect: () => copy(component.purl, 'PURL') },
    { label: 'Copy ID', icon: Hash, onSelect: () => copy(component.id, 'ID') },
  ]

  return (
    <>
      <TooltipProvider>
        <DetailSheet
          open={open}
          onOpenChange={onOpenChange}
          panel={activeTab}
          header={
            <DetailHeader
              title={component.name}
              badges={
                <>
                  <Badge variant="outline" className="font-mono text-xs">
                    v{component.version}
                  </Badge>
                  <EcosystemBadge ecosystem={component.ecosystem} />
                  {component.isDirect ? (
                    <Badge variant="secondary" className="text-xs">
                      Direct
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="gap-1 text-xs">
                      <GitBranch className="h-3 w-3" />
                      Transitive
                    </Badge>
                  )}
                </>
              }
              meta={[component.type, component.licenseId || null]}
              actions={
                component.homepage || component.repositoryUrl ? (
                  <>
                    {component.homepage && (
                      <Button asChild size="sm" variant="outline">
                        <a
                          href={sanitizeExternalUrl(component.homepage)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <ExternalLink className="h-4 w-4" />
                          Homepage
                        </a>
                      </Button>
                    )}
                    {component.repositoryUrl && (
                      <Button asChild size="sm" variant="outline">
                        <a
                          href={sanitizeExternalUrl(component.repositoryUrl)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <GitBranch className="h-4 w-4" />
                          Repository
                        </a>
                      </Button>
                    )}
                  </>
                ) : undefined
              }
              menu={menu}
              onClose={() => onOpenChange(false)}
            />
          }
          tabs={<DetailTabs tabs={tabs} value={activeTab} onValueChange={setActiveTab} />}
        >
          {activeTab === 'overview' && (
            <div className="space-y-5">
              <DetailStatGrid aria-label="Key numbers">
                <DetailStat
                  label="Risk score"
                  value={`${component.riskScore}/100`}
                  tone={riskTone(component.riskScore)}
                  caption={
                    component.riskScore >= 70
                      ? 'Critical risk'
                      : component.riskScore >= 40
                        ? 'Medium risk'
                        : 'Low risk'
                  }
                />
                <DetailStat
                  label="CVEs"
                  value={vulnsLoading && !vulnsData ? '…' : distinctCveCount}
                  tone={distinctCveCount > 0 ? 'destructive' : 'default'}
                  caption={
                    distinctCveCount === 0
                      ? 'No issues'
                      : worst
                        ? `Worst: ${worst.severity}${worst.in_cisa_kev ? ' · KEV' : ''}`
                        : undefined
                  }
                />
                <DetailStat
                  label="Used by assets"
                  value={assetsLoading && !assetsData ? '…' : usedByAssetsCount}
                />
                <DetailStat
                  label="License risk"
                  value={<LicenseRiskBadge risk={component.licenseRisk} showTooltip={false} />}
                />
              </DetailStatGrid>

              <DetailSections>
                {component.description && (
                  <DetailSection title="Description">
                    <p className="text-sm text-muted-foreground">{component.description}</p>
                  </DetailSection>
                )}

                <DetailSection title="License" icon={Scale}>
                  <DetailFieldGrid>
                    <DetailField label="License">
                      <span className="font-mono">{component.licenseId || 'Unknown'}</span>
                    </DetailField>
                    <DetailField label="Category">
                      <LicenseCategoryBadge category={component.licenseCategory} />
                    </DetailField>
                  </DetailFieldGrid>
                </DetailSection>

                <DetailSection title="Package" icon={Package}>
                  <DetailFieldGrid>
                    <DetailField label="Type">
                      <span className="capitalize">{component.type}</span>
                    </DetailField>
                    <DetailField label="Ecosystem">
                      <EcosystemBadge ecosystem={component.ecosystem} />
                    </DetailField>
                    <DetailField label="Dependency">
                      {component.isDirect ? 'Direct' : `Transitive (depth ${component.depth})`}
                    </DetailField>
                    <DetailField label="PURL" full>
                      <span className="font-mono text-xs break-all">{component.purl}</span>
                    </DetailField>
                    {component.isOutdated && component.latestVersion && (
                      <DetailField label="Update available">
                        <Badge
                          variant="outline"
                          className="gap-1 border-warning/40 bg-warning/10 font-mono text-warning"
                        >
                          <Clock className="h-3 w-3" />
                          {component.latestVersion}
                        </Badge>
                      </DetailField>
                    )}
                  </DetailFieldGrid>
                </DetailSection>

                <DetailSection title="Reach in your environment" icon={Server}>
                  <DetailFieldGrid>
                    <DetailField label="Used by assets">
                      <button
                        type="button"
                        onClick={() => setActiveTab('assets')}
                        className="inline-flex items-center gap-1 font-medium hover:underline disabled:cursor-default disabled:no-underline"
                        disabled={usedByAssetsCount === 0}
                      >
                        <span>{usedByAssetsCount}</span>
                        {usedByAssetsCount > 0 && <ChevronRight className="h-3 w-3" />}
                      </button>
                    </DetailField>
                    <DetailField label="Known CVEs">
                      <button
                        type="button"
                        onClick={() => setActiveTab('vulnerabilities')}
                        className="inline-flex items-center gap-1 font-medium hover:underline disabled:cursor-default disabled:no-underline"
                        disabled={distinctCveCount === 0}
                      >
                        <span className={cn(distinctCveCount > 0 && 'text-destructive')}>
                          {distinctCveCount}
                        </span>
                        {distinctCveCount > 0 && <ChevronRight className="h-3 w-3" />}
                      </button>
                    </DetailField>
                  </DetailFieldGrid>
                </DetailSection>

                <DetailSection title="Timeline" icon={Clock}>
                  <DetailFieldGrid>
                    <DetailField label="First seen">
                      {new Date(component.firstSeen).toLocaleDateString()}
                    </DetailField>
                    <DetailField label="Last seen">
                      {new Date(component.lastSeen).toLocaleDateString()}
                    </DetailField>
                  </DetailFieldGrid>
                </DetailSection>
              </DetailSections>
            </div>
          )}

          {/* CVEs: paginated, click a row to drill into the CVE drawer */}
          {activeTab === 'vulnerabilities' &&
            (vulnsError ? (
              <ErrorState title="CVEs" error={vulnsError} />
            ) : vulnsLoading && !vulnsData ? (
              <TabLoading />
            ) : distinctCveCount === 0 ? (
              <EmptyState
                icon={CheckCircle}
                title="No CVEs detected"
                description="No open findings link this component to any CVE in your tenant."
              />
            ) : (
              <DetailSection
                title={`${distinctCveCount} distinct CVE${distinctCveCount === 1 ? '' : 's'}`}
              >
                <p className="text-xs text-muted-foreground">
                  Sorted by severity, then KEV status, then CVSS. Choose a row for the full CVE.
                </p>
                <ul className="divide-y rounded-lg border">
                  {vulnsData?.data.map((v) => (
                    <li key={v.vulnerability_id}>
                      <button
                        type="button"
                        className="flex w-full flex-col gap-1.5 px-3 py-2.5 text-start hover:bg-muted/50"
                        onClick={() =>
                          setSelectedVuln({
                            id: v.vulnerability_id,
                            fallback: vulnFallbackFromRow(v),
                          })
                        }
                      >
                        <span className="flex w-full flex-wrap items-center gap-2">
                          <span className="font-mono text-sm font-medium">{v.cve_id}</span>
                          <SeverityBadge severity={v.severity as Severity} />
                          {v.in_cisa_kev && (
                            <Badge
                              variant="outline"
                              className="border-destructive/30 bg-destructive/10 text-xs text-destructive"
                            >
                              CISA KEV
                            </Badge>
                          )}
                          {v.exploit_available && (
                            <Badge
                              variant="outline"
                              className="gap-1 border-warning/40 bg-warning/10 text-xs text-warning"
                            >
                              <Zap className="h-3 w-3" />
                              Exploit
                            </Badge>
                          )}
                          {v.cvss_score != null && (
                            <span className="ms-auto text-xs text-muted-foreground tabular-nums">
                              CVSS {v.cvss_score.toFixed(1)}
                            </span>
                          )}
                        </span>
                        <span className="line-clamp-2 text-sm">{v.title}</span>
                        <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                          <span className="inline-flex items-center gap-1">
                            <Server className="h-3 w-3" />
                            {v.affected_assets_count} asset
                            {v.affected_assets_count === 1 ? '' : 's'}
                          </span>
                          {v.open_finding_count > 0 ? (
                            <span className="text-destructive">
                              {v.open_finding_count} open / {v.total_finding_count} finding
                              {v.total_finding_count === 1 ? '' : 's'}
                            </span>
                          ) : (
                            <span>{v.total_finding_count} finding(s)</span>
                          )}
                          {v.epss_score != null && (
                            <span>EPSS: {formatEpssScore(v.epss_score)}</span>
                          )}
                          {v.fixed_versions.length > 0 && (
                            <span className="inline-flex items-center gap-1 text-success">
                              <CheckCircle className="h-3 w-3" />
                              Fix: {v.fixed_versions[0]}
                              {v.fixed_versions.length > 1 && ` (+${v.fixed_versions.length - 1})`}
                            </span>
                          )}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>

                {(vulnsData?.total_pages ?? 1) > 1 && (
                  <PaginationFooter
                    page={vulnsPage}
                    totalPages={vulnsData?.total_pages ?? 1}
                    pageSize={VULNS_PER_PAGE}
                    total={distinctCveCount}
                    rendered={vulnsData?.data?.length ?? 0}
                    onPageChange={setVulnsPage}
                  />
                )}
              </DetailSection>
            ))}

          {/* Used-by assets: blast-radius reverse lookup */}
          {activeTab === 'assets' &&
            (assetsError ? (
              <ErrorState title="assets" error={assetsError} />
            ) : assetsLoading && !assetsData ? (
              <TabLoading />
            ) : (assetsData?.data?.length ?? 0) === 0 ? (
              <EmptyState
                icon={Server}
                title="Not used by any asset"
                description="No asset in this tenant currently links to this component."
              />
            ) : (
              <DetailSection
                title={`Used by ${usedByAssetsCount} asset${usedByAssetsCount === 1 ? '' : 's'}`}
              >
                <p className="text-xs text-muted-foreground">
                  Sorted by criticality, then risk score. Internet-exposed assets first.
                </p>
                <ul className="divide-y rounded-lg border">
                  {assetsData?.data.map((u) => (
                    <li key={u.dependency_id}>
                      <button
                        type="button"
                        className="flex w-full items-start justify-between gap-2 px-3 py-2.5 text-start hover:bg-muted/50"
                        onClick={() => {
                          onOpenChange(false)
                          router.push(`/assets/${u.asset_id}`)
                        }}
                      >
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <Server className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                            <span className="font-medium break-all">{u.asset_name}</span>
                            <Badge variant="outline" className="text-xs capitalize">
                              {u.asset_type.replace(/_/g, ' ')}
                            </Badge>
                            {u.is_internet_accessible && (
                              <Badge
                                variant="outline"
                                className="gap-1 border-warning/40 bg-warning/10 text-xs text-warning"
                              >
                                <Globe className="h-3 w-3" />
                                Internet
                              </Badge>
                            )}
                          </span>
                          <span className="mt-1.5 flex flex-wrap items-center gap-2">
                            <Badge
                              variant="outline"
                              className={cn('text-xs capitalize', CRITICALITY_BADGE[u.criticality])}
                            >
                              {u.criticality}
                            </Badge>
                            <Badge variant="secondary" className="gap-1 text-xs">
                              <Layers className="h-3 w-3" />
                              {u.is_direct ? 'direct' : `transitive (depth ${u.depth})`}
                            </Badge>
                            {u.vulnerability_count > 0 && (
                              <Badge
                                variant="outline"
                                className="gap-1 border-destructive/30 bg-destructive/10 text-xs text-destructive"
                              >
                                <AlertTriangle className="h-3 w-3" />
                                {u.vulnerability_count} vuln
                                {u.vulnerability_count === 1 ? '' : 's'}
                              </Badge>
                            )}
                          </span>
                          {u.manifest_file && (
                            <code className="mt-1.5 block font-mono text-xs break-all text-muted-foreground">
                              {u.manifest_path
                                ? `${u.manifest_path} (${u.manifest_file})`
                                : u.manifest_file}
                            </code>
                          )}
                        </span>
                        <span className="shrink-0 text-end">
                          <span className="block text-xs text-muted-foreground">Risk</span>
                          <span className="block text-base font-semibold tabular-nums">
                            {u.risk_score}
                          </span>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>

                {(assetsData?.total_pages ?? 1) > 1 && (
                  <PaginationFooter
                    page={assetsPage}
                    totalPages={assetsData?.total_pages ?? 1}
                    pageSize={ASSETS_PER_PAGE}
                    total={usedByAssetsCount}
                    rendered={assetsData?.data?.length ?? 0}
                    onPageChange={setAssetsPage}
                  />
                )}
              </DetailSection>
            ))}
        </DetailSheet>
      </TooltipProvider>

      {/* Nested vulnerability detail sheet — opens when user clicks a CVE row */}
      <VulnerabilityDetailSheet
        vulnerabilityId={selectedVuln?.id ?? null}
        fallback={selectedVuln?.fallback ?? null}
        open={selectedVuln !== null}
        onOpenChange={(o) => !o && setSelectedVuln(null)}
      />
    </>
  )
}
