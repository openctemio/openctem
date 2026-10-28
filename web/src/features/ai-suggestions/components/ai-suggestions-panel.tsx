'use client'

import { useCallback, useMemo, useState } from 'react'
import { Sparkles } from 'lucide-react'
import { useSWRConfig } from 'swr'

import { useTranslation } from '@/context/i18n-provider'
import { usePermissionsSafe } from '@/context/permission-provider'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { Permission } from '@/lib/permissions/constants'

import { useFindingAISuggestions, type AISuggestion } from '../api/ai-governance-api'
import { KIND_ORDER, VISIBLE_STATES } from '../lib/suggestion-payload'
import { AIRunDrawer } from './ai-run-drawer'
import { AISuggestionCard, kindLabel } from './ai-suggestion-card'

/**
 * The finding's AI suggestions, grouped by kind: the ones still to decide and
 * the ones applied or waiting for approval. Renders nothing when there are
 * none, when the caller may not read AI results, or when the API does not
 * offer suggestions yet (404).
 */
export function AISuggestionsPanel({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  const { hasPermission: can } = usePermissionsSafe()
  const { mutate: globalMutate } = useSWRConfig()
  const canRead = can(Permission.AITriageRead) && can(Permission.FindingsRead)
  const { data, mutate } = useFindingAISuggestions(canRead ? findingId : null)
  const [whyRun, setWhyRun] = useState<string | null>(null)

  const groups = useMemo(() => {
    const visible = (data ?? []).filter((s) => VISIBLE_STATES.has(s.state))
    return KIND_ORDER.map((kind) => ({
      kind,
      items: visible.filter((s) => s.kind === kind),
    })).filter((g) => g.items.length > 0)
  }, [data])

  // A decision can change the finding itself (severity, status): refresh it too.
  const onChanged = useCallback(async () => {
    await mutate()
    const prefix = `/api/v1/findings/${encodeURIComponent(findingId)}`
    await globalMutate(
      (key) => typeof key === 'string' && key.startsWith(prefix) && !key.includes('/ai/'),
      undefined,
      { revalidate: true }
    )
  }, [mutate, globalMutate, findingId])

  const count = groups.reduce((n, g) => n + g.items.length, 0)
  if (count === 0) return null

  return (
    <DetailSection
      title={t('findings.aiSuggestions.title', 'AI suggestions')}
      icon={Sparkles}
      count={count}
    >
      <div className="space-y-4">
        {groups.map((g) => (
          <div key={g.kind} className="space-y-2">
            <h4 className="text-xs font-medium text-muted-foreground">{kindLabel(t, g.kind)}</h4>
            {g.items.map((s: AISuggestion) => (
              <AISuggestionCard key={s.id} suggestion={s} onChanged={onChanged} onWhy={setWhyRun} />
            ))}
          </div>
        ))}
      </div>
      <AIRunDrawer runId={whyRun} onOpenChange={(open) => !open && setWhyRun(null)} />
    </DetailSection>
  )
}
