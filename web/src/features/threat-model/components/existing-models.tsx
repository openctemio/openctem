'use client'

import { Tag } from '@/components/ui/tag'
import { useTranslation } from '@/context/i18n-provider'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { EmptyState } from '@/features/shared'
import { cn } from '@/lib/utils'
import { ChevronRight, ScanSearch } from 'lucide-react'
import type { ThreatModelSummary } from '../types'
import { formatDateTime } from '../lib/format-date'

interface ExistingModelsProps {
  models: ThreatModelSummary[]
  selectedId?: string | null
  onOpen: (id: string) => void
}

/** Previously generated threat models. Open one without regenerating. */
export function ExistingModels({ models, selectedId, onOpen }: ExistingModelsProps) {
  const { t, locale } = useTranslation()
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">
          {t('threatModel.existing.title', 'Threat models')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {models.length === 0 ? (
          <EmptyState
            icon={ScanSearch}
            title={t('threatModel.existing.emptyTitle', 'No threat models yet')}
            description={t(
              'threatModel.existing.emptyDescription',
              'Generate one from a crown-jewel scope above to get started.'
            )}
            card={false}
          />
        ) : (
          <ul className="divide-y">
            {models.map((m) => {
              const coverage = Math.round(m.coverage_pct)
              return (
                <li key={m.id}>
                  <button
                    type="button"
                    onClick={() => onOpen(m.id)}
                    className={cn(
                      'hover:bg-muted/50 flex w-full items-center gap-4 rounded-md px-2 py-3 text-start transition-colors',
                      selectedId === m.id && 'bg-muted'
                    )}
                  >
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-medium">{m.name}</p>
                      <p className="text-muted-foreground text-xs">
                        {t('threatModel.generatedWithVersion', 'Generated {date} · {version}', {
                          date: formatDateTime(m.generated_at, locale),
                          version: m.technique_dataset_version,
                        })}
                      </p>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-2 sm:flex-row sm:items-center">
                      {m.threats_open > 0 && (
                        <Tag
                          label={t('threatModel.existing.open', '{n} open', { n: m.threats_open })}
                        />
                      )}
                      <Badge variant="secondary">
                        {t(
                          'threatModel.existing.threats',
                          '{n, plural, one {# threat} other {# threats}}',
                          { n: m.threats_total }
                        )}
                      </Badge>
                      <span className="text-muted-foreground w-24 text-end text-sm tabular-nums">
                        {t('threatModel.existing.covered', '{pct}% covered', { pct: coverage })}
                      </span>
                      <ChevronRight className="text-muted-foreground h-4 w-4" />
                    </div>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
