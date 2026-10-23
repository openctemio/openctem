'use client'

import { useMemo, useState } from 'react'
import { Main } from '@/components/layout'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState, GatedSectionTabs, PageHeader } from '@/features/shared'
import { THREAT_MODEL_SECTION_TABS } from '@/config/section-tabs'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ArrowLeft, Loader2, RefreshCw } from 'lucide-react'
import { Can, Permission } from '@/lib/permissions'
import { toast } from 'sonner'
import {
  CoverageHeatmap,
  CoverageStats,
  ExistingModels,
  MitreFooter,
  ScopePicker,
  ThreatModelTable,
  generateThreatModel,
  useAssetNameMap,
  useAttackerProfileMap,
  useCrownJewels,
  useThreatModel,
  useThreatModels,
} from '@/features/threat-model'
import type { ThreatFilters } from '@/features/threat-model'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { useUrlFilter } from '@/hooks/use-url-param'
import { formatDateTime } from '@/features/threat-model/lib/format-date'

const DEFAULT_FILTERS: ThreatFilters = {
  status: 'all',
  tactic: 'all',
  attacker: 'all',
  technique: 'all',
}

export default function ThreatModelPage() {
  const { t, locale } = useTranslation()
  // The open model and its tab live in the URL so a model can be linked to.
  const [modelParam, setModelParam] = useUrlFilter('model', '')
  const [tab, setTab] = useUrlFilter('tab', 'threats')
  const selectedModelId = modelParam || null
  const setSelectedModelId = (id: string | null) => {
    setTab('threats')
    setModelParam(id ?? '')
  }
  const [isGenerating, setIsGenerating] = useState(false)
  const [filters, setFilters] = useState<ThreatFilters>(DEFAULT_FILTERS)

  const {
    models,
    isLoading: modelsLoading,
    error: modelsError,
    mutate: mutateModels,
  } = useThreatModels()
  const { crownJewels, isLoading: crownJewelsLoading } = useCrownJewels()
  const {
    model,
    isLoading: modelLoading,
    error: modelError,
    mutate: mutateModel,
  } = useThreatModel(selectedModelId)
  // attacker_profiles is a separate (Phase-3 gated) module from this page's
  // attack_surface module; skip its fetch when disabled (rows fall back to id).
  const attackerProfilesEnabled = useModuleEnabled('attacker_profiles')
  const { profileMap } = useAttackerProfileMap(attackerProfilesEnabled)

  const assetIds = useMemo(() => {
    if (!model?.threats) return []
    const ids: string[] = []
    for (const th of model.threats) {
      ids.push(th.entry_point_asset_id, th.hop_asset_id, th.target_asset_id)
    }
    return ids
  }, [model])
  const { nameFor } = useAssetNameMap(assetIds)

  const handleGenerate = async (scopeRefId: string) => {
    setIsGenerating(true)
    try {
      const generated = await generateThreatModel('crown_jewel', scopeRefId)
      await mutateModels()
      setSelectedModelId(generated.id)
      setFilters(DEFAULT_FILTERS)
      toast.success(t('threatModel.toast.generated', 'Threat model generated.'))
    } catch {
      toast.error(t('threatModel.toast.generateFailed', 'Could not generate the threat model.'))
    } finally {
      setIsGenerating(false)
    }
  }

  const handleRefresh = async () => {
    if (!model) return
    setIsGenerating(true)
    try {
      const generated = await generateThreatModel(model.scope_type, model.scope_ref_id)
      await mutateModels()
      setSelectedModelId(generated.id)
      toast.success(t('threatModel.toast.refreshed', 'Threat model refreshed.'))
    } catch {
      toast.error(t('threatModel.toast.refreshFailed', 'Could not refresh the threat model.'))
    } finally {
      setIsGenerating(false)
    }
  }

  const openModel = (id: string) => {
    setSelectedModelId(id)
    setFilters(DEFAULT_FILTERS)
  }

  // ----- Detail view -----
  if (selectedModelId) {
    return (
      <Main>
        <PageHeader
          title={model?.name ?? t('threatModel.title', 'Threat model')}
          description={
            model
              ? t('threatModel.detail.generated', 'Generated {date} · ATT&CK {version}', {
                  date: formatDateTime(model.generated_at, locale),
                  version: model.technique_dataset_version,
                })
              : t('threatModel.detail.loading', 'Loading threat model…')
          }
        >
          <Button variant="outline" size="sm" onClick={() => setSelectedModelId(null)}>
            <ArrowLeft className="me-2 h-4 w-4" />
            {t('threatModel.detail.allModels', 'All models')}
          </Button>
          <Can
            permission={Permission.AssetsWrite}
            mode="disable"
            disabledTooltip={t('threatModel.detail.needWrite', 'You need assets:write to refresh')}
          >
            <Button size="sm" onClick={handleRefresh} disabled={isGenerating || !model}>
              {isGenerating ? (
                <Loader2 className="me-2 h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="me-2 h-4 w-4" />
              )}
              {t('threatModel.detail.refresh', 'Refresh')}
            </Button>
          </Can>
        </PageHeader>
        <GatedSectionTabs
          tabs={THREAT_MODEL_SECTION_TABS}
          label={t('threatModel.sections', 'Threat model sections')}
          className="mt-4 mb-0"
        />

        {modelError ? (
          <div className="mt-5">
            <ErrorState
              title={t('threatModel.thisModel', 'this threat model')}
              error={modelError}
              onRetry={() => mutateModel()}
            />
          </div>
        ) : modelLoading || !model ? (
          <div className="mt-5 space-y-5">
            <Skeleton className="h-[68px] w-full rounded-xl" />
            <Skeleton className="h-96 w-full" />
          </div>
        ) : (
          <div className="mt-5 space-y-5">
            <CoverageStats model={model} />
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList>
                <TabsTrigger value="threats">{t('threatModel.tab.threats', 'Threats')}</TabsTrigger>
                <TabsTrigger value="coverage">
                  {t('threatModel.tab.coverage', 'Coverage matrix')}
                </TabsTrigger>
              </TabsList>
              <TabsContent value="threats" className="mt-4">
                <ThreatModelTable
                  threats={model.threats ?? []}
                  filters={filters}
                  onFiltersChange={setFilters}
                  profileMap={profileMap}
                  nameFor={nameFor}
                />
              </TabsContent>
              <TabsContent value="coverage" className="mt-4">
                <CoverageHeatmap modelId={model.id} modelName={model.name} />
              </TabsContent>
            </Tabs>
            <MitreFooter />
          </div>
        )}
      </Main>
    )
  }

  // ----- Landing / list view -----
  return (
    <Main>
      <PageHeader
        title={t('threatModel.title', 'Threat model')}
        description={t(
          'threatModel.description',
          'Attack techniques derived per crown jewel, mapped to MITRE ATT&CK and scored by coverage.'
        )}
      />
      <GatedSectionTabs
        tabs={THREAT_MODEL_SECTION_TABS}
        label={t('threatModel.sections', 'Threat model sections')}
        className="mt-4 mb-0"
      />
      <div className="mt-5 space-y-5">
        <ScopePicker
          crownJewels={crownJewels}
          isLoading={crownJewelsLoading}
          isGenerating={isGenerating}
          onGenerate={handleGenerate}
        />
        {modelsError ? (
          <ErrorState
            title={t('threatModel.models', 'threat models')}
            error={modelsError}
            onRetry={() => mutateModels()}
          />
        ) : modelsLoading ? (
          <Card>
            <CardContent className="space-y-3 py-6">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </CardContent>
          </Card>
        ) : (
          <ExistingModels models={models} selectedId={selectedModelId} onOpen={openModel} />
        )}
        <MitreFooter />
      </div>
    </Main>
  )
}
