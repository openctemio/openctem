'use client'

import { Bot, Database, FileCode2, Gauge } from 'lucide-react'

import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { AIBadge, aiSourceOfExecutor } from '@/features/shared/components/ai-badge'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
  DetailSections,
} from '@/features/shared/components/detail-sheet'
import { DetailHeader, DetailSheet } from '@/features/shared/components/detail-sheet-layout'
import { TruncatedText } from '@/features/shared/components/truncated-text'

import { useAIRun, type AIRun } from '../api/ai-governance-api'

const EXECUTOR_FALLBACK: Record<string, string> = {
  builtin: 'Built-in AI triage',
  platform_worker: 'Platform AI analyst',
  tenant_worker: 'Your organization’s AI analyst',
}

const DATA_CLASS_FALLBACK: Record<string, string> = {
  public: 'Public',
  internal: 'Internal',
  restricted: 'Restricted',
  tenant_only: 'Stays in your organization',
}

/**
 * The "Why" drawer: what the run sent and withheld, which model and prompt
 * template answered, the output schema and digests, and what it cost. Every
 * value is server-recorded provenance shown as text.
 */
export function AIRunDrawer({
  runId,
  onOpenChange,
}: {
  runId: string | null
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { data: run, isLoading } = useAIRun(runId)

  return (
    <DetailSheet
      open={runId !== null}
      onOpenChange={onOpenChange}
      width="lg"
      header={
        <DetailHeader
          title={t('findings.aiSuggestions.run.title', 'Why the AI suggested this')}
          badges={run ? <AIBadge source={aiSourceOfExecutor(run.executor)} /> : undefined}
          onClose={() => onOpenChange(false)}
        />
      }
    >
      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : run ? (
        <RunDetails run={run} />
      ) : (
        <p className="text-sm text-muted-foreground">
          {t('findings.aiSuggestions.run.unavailable', 'The record of this run is not available.')}
        </p>
      )}
    </DetailSheet>
  )
}

function FieldList({ items, empty }: { items: string[]; empty: string }) {
  if (items.length === 0) return <span className="text-muted-foreground">{empty}</span>
  return (
    <ul className="flex flex-wrap gap-1.5">
      {items.map((f) => (
        <li key={f} className="rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-xs">
          <TruncatedText value={f} className="max-w-[240px]" />
        </li>
      ))}
    </ul>
  )
}

function RunDetails({ run }: { run: AIRun }) {
  const { t, locale } = useTranslation()
  const none = t('findings.aiSuggestions.run.none', 'None')
  const cost = (run.cost_micro_usd / 1_000_000).toLocaleString(locale, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 4,
  })
  return (
    <DetailSections>
      <DetailSection title={t('findings.aiSuggestions.run.model', 'Model')} icon={Bot}>
        <DetailFieldGrid>
          <DetailField label={t('findings.aiSuggestions.run.executor', 'Executor')}>
            {t(
              `findings.aiSuggestions.run.executorName.${run.executor}`,
              EXECUTOR_FALLBACK[run.executor] ?? run.executor
            )}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.provider', 'Provider')}>
            {run.provider ? <TruncatedText value={run.provider} /> : null}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.modelId', 'Model id')}>
            {run.model ? <TruncatedText value={run.model} className="font-mono" /> : null}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.status', 'Status')}>
            {t(`findings.aiSuggestions.run.statusName.${run.status}`, run.status)}
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>

      <DetailSection title={t('findings.aiSuggestions.run.data', 'What was sent')} icon={Database}>
        <DetailFieldGrid>
          <DetailField label={t('findings.aiSuggestions.run.dataClass', 'Data class')}>
            {t(
              `findings.aiSuggestions.run.dataClassName.${run.data_class}`,
              DATA_CLASS_FALLBACK[run.data_class] ?? run.data_class
            )}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.bundleDigest', 'Bundle digest')}>
            {run.bundle_digest ? (
              <TruncatedText value={run.bundle_digest} className="font-mono" middle={24} />
            ) : null}
          </DetailField>
          <DetailField full label={t('findings.aiSuggestions.run.fieldsSent', 'Fields sent')}>
            <FieldList items={run.fields_sent ?? []} empty={none} />
          </DetailField>
          <DetailField
            full
            label={t('findings.aiSuggestions.run.fieldsWithheld', 'Fields withheld')}
          >
            <FieldList items={run.fields_withheld ?? []} empty={none} />
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>

      <DetailSection
        title={t('findings.aiSuggestions.run.prompt', 'Prompt and output')}
        icon={FileCode2}
      >
        <DetailFieldGrid>
          <DetailField label={t('findings.aiSuggestions.run.template', 'Prompt template')}>
            {run.prompt_template_id ? (
              <TruncatedText value={run.prompt_template_id} className="font-mono" />
            ) : null}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.templateDigest', 'Template digest')}>
            {run.prompt_template_digest ? (
              <TruncatedText value={run.prompt_template_digest} className="font-mono" middle={24} />
            ) : null}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.outputSchema', 'Output schema')}>
            {run.output_schema ? (
              <TruncatedText value={run.output_schema} className="font-mono" />
            ) : null}
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>

      <DetailSection title={t('findings.aiSuggestions.run.usage', 'Usage')} icon={Gauge}>
        <DetailFieldGrid>
          <DetailField label={t('findings.aiSuggestions.run.tokens', 'Tokens')}>
            {t('findings.aiSuggestions.run.tokensValue', '{in} in, {out} out', {
              in: run.tokens_in.toLocaleString(locale),
              out: run.tokens_out.toLocaleString(locale),
            })}
          </DetailField>
          <DetailField label={t('findings.aiSuggestions.run.cost', 'Cost')}>{cost}</DetailField>
          <DetailField label={t('findings.aiSuggestions.run.suggestions', 'Suggestions')}>
            {String(run.suggestions?.length ?? 0)}
          </DetailField>
        </DetailFieldGrid>
      </DetailSection>
    </DetailSections>
  )
}
