'use client'

import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Main } from '@/components/layout'
import { PageHeader, EmptyState } from '@/features/shared'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useUrlFilter } from '@/hooks/use-url-param'
import { formatEpssPercentile, formatEpssScore, formatEpssTopPercent } from '@/lib/epss'
import {
  TrendingUp,
  AlertOctagon,
  Shield,
  Search,
  RefreshCw,
  Loader2,
  ExternalLink,
  Info,
} from 'lucide-react'
import { toast } from 'sonner'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'

import { useThreatIntelStats, enrichCVE } from '@/features/threat-intel/hooks'
import {
  ThreatIntelOverview,
  SyncStatusManager,
  CompactSyncStatus,
  ThreatActorsPanel,
} from '@/features/threat-intel/components'
import { EPSSScoreBadge, EPSSScoreMeter } from '@/features/shared/components/epss-score-badge'
import { KEVIndicatorBadge, KEVStatus } from '@/features/shared/components/kev-indicator-badge'
import type { CVEEnrichment } from '@/lib/api/threatintel-types'
import { SafeExternalLink } from '@/components/safe-external-link'

const TABS = ['overview', 'actors', 'lookup', 'sync']

export default function ThreatIntelPage() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id || null

  // Use unified stats hook - single API call for all data
  const {
    epssStats,
    kevStats,
    syncStatuses,
    isLoading,
    mutate: refresh,
  } = useThreatIntelStats(tenantId)

  const handleRefreshAll = () => {
    refresh()
  }

  const lastSync = syncStatuses.length > 0 ? syncStatuses[0].last_sync_at : undefined

  const [tabParam, setTab] = useUrlFilter('tab', 'overview')
  const activeTab = TABS.includes(tabParam) ? tabParam : 'overview'

  return (
    <Main>
      <PageHeader title={t('threatIntel.title')} description={t('threatIntel.description')}>
        <CompactSyncStatus statuses={syncStatuses} />
        <Button variant="outline" size="sm" onClick={handleRefreshAll} disabled={isLoading}>
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin sm:me-2" />
          ) : (
            <RefreshCw className="h-4 w-4 sm:me-2" />
          )}
          <span className="sr-only sm:not-sr-only">{t('threatIntel.refresh')}</span>
        </Button>
      </PageHeader>

      {/* The active tab lives in the URL (?tab=) so each view can be linked. */}
      <Tabs value={activeTab} onValueChange={setTab} className="mt-4">
        <TabsList>
          <TabsTrigger value="overview">{t('threatIntel.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="actors">{t('threatIntel.tabs.actors')}</TabsTrigger>
          <TabsTrigger value="lookup">{t('threatIntel.tabs.lookup')}</TabsTrigger>
          <TabsTrigger value="sync">{t('threatIntel.tabs.sync')}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-5 space-y-5">
          <ThreatIntelOverview
            epssStats={epssStats}
            kevStats={kevStats}
            lastSyncAt={lastSync}
            isLoading={isLoading}
          />

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <InfoCard
              title={t('threatIntel.info.epssTitle')}
              icon={TrendingUp}
              description={t('threatIntel.info.epssDescription')}
              links={[
                { label: t('threatIntel.info.epssLink'), url: 'https://www.first.org/epss/' },
              ]}
            />
            <InfoCard
              title={t('threatIntel.info.kevTitle')}
              icon={AlertOctagon}
              description={t('threatIntel.info.kevDescription')}
              links={[
                {
                  label: t('threatIntel.info.kevLink'),
                  url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                },
              ]}
            />
          </div>
        </TabsContent>

        <TabsContent value="actors" className="mt-5">
          <ThreatActorsPanel />
        </TabsContent>

        <TabsContent value="lookup" className="mt-5">
          <CVELookup />
        </TabsContent>

        <TabsContent value="sync" className="mt-5">
          <SyncStatusManager statuses={syncStatuses} onRefresh={refresh} />
        </TabsContent>
      </Tabs>
    </Main>
  )
}

interface InfoCardProps {
  title: string
  icon: typeof Shield
  description: string
  links?: Array<{ label: string; url: string }>
}

function InfoCard({ title, icon: Icon, description, links }: InfoCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="h-4 w-4 text-muted-foreground" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">{description}</p>
        {links && links.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {links.map((link) => (
              <SafeExternalLink
                key={link.url}
                href={link.url}
                className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
              >
                {link.label}
                <ExternalLink className="h-3 w-3" />
              </SafeExternalLink>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function CVELookup() {
  const { t } = useTranslation()
  const [cveId, setCveId] = useState('')
  const [isLookingUp, setIsLookingUp] = useState(false)
  const [result, setResult] = useState<CVEEnrichment | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleLookup = async () => {
    if (!cveId.trim()) {
      toast.error(t('threatIntel.lookup.enterId'))
      return
    }

    // Validate CVE format
    const cveRegex = /^CVE-\d{4}-\d{4,}$/i
    if (!cveRegex.test(cveId.trim())) {
      toast.error(t('threatIntel.lookup.invalidFormat'))
      return
    }

    setIsLookingUp(true)
    setError(null)
    setResult(null)

    try {
      const enrichment = await enrichCVE(cveId.trim().toUpperCase())
      setResult(enrichment)
    } catch (err) {
      setError(t('threatIntel.lookup.notFound'))
      console.error(err)
    } finally {
      setIsLookingUp(false)
    }
  }

  return (
    <div className="space-y-5">
      {/* Search Input */}
      <Card>
        <CardHeader>
          <CardTitle>{t('threatIntel.lookup.title')}</CardTitle>
          <CardDescription>{t('threatIntel.lookup.description')}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <div className="relative min-w-0 flex-1">
              <Search className="absolute start-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t('threatIntel.lookup.placeholder')}
                aria-label={t('threatIntel.lookup.idLabel')}
                value={cveId}
                onChange={(e) => setCveId(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
                className="ps-9"
              />
            </div>
            <Button onClick={handleLookup} disabled={isLookingUp}>
              {isLookingUp ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <Search className="me-2 h-4 w-4" />
              )}
              {t('threatIntel.lookup.button')}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Error State */}
      {error && (
        <Alert variant="destructive">
          <Info />
          <AlertTitle>{t('threatIntel.lookup.failed')}</AlertTitle>
          <AlertDescription>
            <p>{error}</p>
            <Button variant="outline" size="sm" className="mt-2" onClick={handleLookup}>
              <RefreshCw className="me-2 h-4 w-4" />
              {t('threatIntel.lookup.retry')}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* CVE Header */}
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <CardTitle className="font-mono">{result.cve_id}</CardTitle>
                <div className="flex items-center gap-2">
                  {result.epss && (
                    <EPSSScoreBadge
                      score={result.epss.score}
                      percentile={result.epss.percentile}
                      showPercentile
                      size="lg"
                    />
                  )}
                  <KEVIndicatorBadge
                    inKEV={!!result.kev}
                    kevData={
                      result.kev
                        ? {
                            date_added: result.kev.date_added,
                            due_date: result.kev.due_date,
                            ransomware_use: result.kev.known_ransomware_campaign_use,
                            notes: result.kev.notes,
                          }
                        : null
                    }
                    size="lg"
                  />
                </div>
              </div>
              <CardDescription>
                {t('threatIntel.lookup.enriched', undefined, {
                  time: new Date(result.enriched_at).toLocaleString(),
                })}
              </CardDescription>
            </CardHeader>
          </Card>

          {/* EPSS Details */}
          {result.epss && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <TrendingUp className="h-4 w-4 text-muted-foreground" />
                  {t('threatIntel.lookup.epssScore')}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <div>
                    <p className="text-sm text-muted-foreground">{t('threatIntel.lookup.score')}</p>
                    <p className="text-2xl font-semibold tabular-nums">
                      {formatEpssScore(result.epss.score, 2)}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {t('threatIntel.lookup.scoreHint')}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">
                      {t('threatIntel.lookup.percentile')}
                    </p>
                    <p className="text-2xl font-semibold tabular-nums">
                      {formatEpssPercentile(result.epss.percentile)}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {t('threatIntel.lookup.percentileHint', undefined, {
                        top: formatEpssTopPercent(result.epss.percentile),
                      })}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">
                      {t('threatIntel.lookup.modelVersion')}
                    </p>
                    <p className="text-lg font-medium">{result.epss.model_version}</p>
                    <p className="text-xs text-muted-foreground">
                      {t('threatIntel.lookup.scoreDate', undefined, {
                        date: new Date(result.epss.score_date).toLocaleDateString(),
                      })}
                    </p>
                  </div>
                </div>
                <EPSSScoreMeter score={result.epss.score} size="lg" showLabel />
              </CardContent>
            </Card>
          )}

          {/* KEV Details */}
          {result.kev ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <AlertOctagon className="h-4 w-4 text-muted-foreground" />
                  {t('threatIntel.lookup.kevEntry')}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <KEVStatus
                  inKEV
                  kevData={{
                    date_added: result.kev.date_added,
                    due_date: result.kev.due_date,
                    ransomware_use: result.kev.known_ransomware_campaign_use,
                    notes: result.kev.notes,
                  }}
                />

                <div className="space-y-3 border-t pt-4">
                  <div>
                    <p className="text-sm font-medium">{t('threatIntel.lookup.vendorProduct')}</p>
                    <p className="text-sm text-muted-foreground">
                      {result.kev.vendor_project} - {result.kev.product}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm font-medium">{t('threatIntel.lookup.vulnName')}</p>
                    <p className="text-sm text-muted-foreground">{result.kev.vulnerability_name}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium">
                      {t('threatIntel.lookup.descriptionLabel')}
                    </p>
                    <p className="text-sm text-muted-foreground">{result.kev.short_description}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium">{t('threatIntel.lookup.requiredAction')}</p>
                    <p className="text-sm text-muted-foreground">{result.kev.required_action}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent>
                <div className="flex items-center gap-3 text-sm text-muted-foreground">
                  <Shield className="h-5 w-5" />
                  <span>{t('threatIntel.lookup.notInKev')}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {/* No Data State */}
          {!result.epss && !result.kev && (
            <EmptyState icon={Info} title={t('threatIntel.lookup.noData')} />
          )}
        </div>
      )}
    </div>
  )
}
