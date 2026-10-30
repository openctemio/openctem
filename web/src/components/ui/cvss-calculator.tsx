'use client'

/**
 * CVSS base-score calculator for versions 3.1 and 4.0.
 *
 * Paste a vector (any base vector; extra non-base metrics are ignored) or
 * pick the metrics; the score is computed per the FIRST specification
 * (@/lib/cvss). Emits the vector and, once every base metric is set, the
 * score.
 */

import * as React from 'react'
import { ChevronDown, RotateCcw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { SEVERITY_BADGE_SOLID } from '@/lib/severity-colors'
import { SEVERITY_LABEL_KEYS, SEVERITY_LABELS, type SeverityLevel } from '@/lib/severity'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import {
  CVSS_METRICS,
  buildCvssVector,
  parseCvssVector,
  scoreCvss,
  type CvssMetrics,
  type CvssVersion,
} from '@/lib/cvss'

const METRIC_NAMES: Record<string, string> = {
  AV: 'Attack vector',
  AC: 'Attack complexity',
  AT: 'Attack requirements',
  PR: 'Privileges required',
  UI: 'User interaction',
  S: 'Scope',
  C: 'Confidentiality',
  I: 'Integrity',
  A: 'Availability',
  VC: 'Confidentiality',
  VI: 'Integrity',
  VA: 'Availability',
  SC: 'Confidentiality',
  SI: 'Integrity',
  SA: 'Availability',
}

const VALUE_NAMES: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  AT: { N: 'None', P: 'Present' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required', P: 'Passive', A: 'Active' },
  S: { U: 'Unchanged', C: 'Changed' },
  CIA: { H: 'High', L: 'Low', N: 'None' },
}

const GROUP_NAMES: Record<string, string> = {
  exploitability: 'Exploitability',
  scope: 'Scope',
  impact: 'Impact',
  subsequent: 'Impact on subsequent systems',
}

function band(score: number): SeverityLevel {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

interface CvssCalculatorProps {
  score: string
  vector: string
  onScoreChange: (score: string) => void
  onVectorChange: (vector: string) => void
}

export function CvssCalculator({ vector, onScoreChange, onVectorChange }: CvssCalculatorProps) {
  const { t } = useTranslation()
  const parsed = React.useMemo(() => parseCvssVector(vector), [vector])
  const [version, setVersion] = React.useState<CvssVersion>(parsed?.version ?? '3.1')
  const metrics: CvssMetrics = parsed && parsed.version === version ? parsed.metrics : {}
  const [text, setText] = React.useState(vector)
  const [textInvalid, setTextInvalid] = React.useState(false)
  const [open, setOpen] = React.useState(!parsed?.complete)

  // Follow vector changes from outside (template, draft restore).
  React.useEffect(() => {
    setText(vector)
    setTextInvalid(false)
    const p = parseCvssVector(vector)
    if (p) setVersion(p.version)
  }, [vector])

  const emit = (v: CvssVersion, m: CvssMetrics) => {
    const next = buildCvssVector(v, m)
    const score = scoreCvss(v, m)
    onVectorChange(next)
    onScoreChange(score === null ? '' : score.toFixed(1))
  }

  const pick = (key: string, value: string) => emit(version, { ...metrics, [key]: value })

  const switchVersion = (v: CvssVersion) => {
    if (v === version) return
    setVersion(v)
    // Metrics differ between versions: start over rather than guess.
    onVectorChange('')
    onScoreChange('')
  }

  const applyText = (raw: string) => {
    setText(raw)
    if (!raw.trim()) {
      setTextInvalid(false)
      onVectorChange('')
      onScoreChange('')
      return
    }
    const p = parseCvssVector(raw)
    setTextInvalid(!p)
    if (p) {
      setVersion(p.version)
      emit(p.version, p.metrics)
    }
  }

  const score = scoreCvss(version, metrics)
  const defs = CVSS_METRICS[version]
  const missing = defs.filter((d) => !metrics[d.key]).length
  const groups = Array.from(new Set(defs.map((d) => d.group)))
  const valueName = (key: string, v: string) => {
    const table = VALUE_NAMES[key] ?? VALUE_NAMES.CIA
    return t(`common.cvss.value.${key in VALUE_NAMES ? key : 'CIA'}.${v}`, table[v] ?? v)
  }

  return (
    <div className="space-y-3 rounded-lg border p-3" data-testid="cvss-calculator">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{t('common.cvss.title', 'CVSS')}</span>
        <div
          role="radiogroup"
          aria-label={t('common.cvss.version', 'CVSS version')}
          className="inline-flex rounded-md border p-0.5"
        >
          {(['3.1', '4.0'] as const).map((v) => (
            <button
              key={v}
              type="button"
              role="radio"
              aria-checked={version === v}
              onClick={() => switchVersion(v)}
              className={cn(
                'rounded px-2 py-0.5 text-xs font-medium',
                version === v
                  ? 'bg-muted text-foreground'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {v}
            </button>
          ))}
        </div>
        <div className="ms-auto flex items-center gap-2" aria-live="polite">
          {score !== null ? (
            <Badge
              className={cn('tabular-nums', SEVERITY_BADGE_SOLID[band(score)])}
              data-testid="cvss-score"
            >
              {score.toFixed(1)},{' '}
              {t(SEVERITY_LABEL_KEYS[band(score)], SEVERITY_LABELS[band(score)])}
            </Badge>
          ) : (
            <span className="text-xs text-muted-foreground">
              {t('common.cvss.remaining', '{count} metrics to set', { count: missing })}
            </span>
          )}
        </div>
      </div>

      <div className="space-y-1">
        <Input
          value={text}
          onChange={(e) => applyText(e.target.value)}
          placeholder={t('common.cvss.pastePlaceholder', 'Paste a vector, e.g. {example}', {
            example:
              version === '3.1'
                ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                : 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
          })}
          aria-label={t('common.cvss.vector', 'CVSS vector')}
          aria-invalid={textInvalid || undefined}
          className="font-mono text-xs"
          spellCheck={false}
        />
        {textInvalid && (
          <p className="text-xs text-destructive">
            {t('common.cvss.invalid', 'Not a CVSS 3.1 or 4.0 base vector.')}
          </p>
        )}
      </div>

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground"
        >
          <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', !open && '-rotate-90')} />
          {open
            ? t('common.cvss.hideMetrics', 'Hide metrics')
            : t('common.cvss.showMetrics', 'Pick metrics')}
        </button>
        {(vector || text) && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs"
            onClick={() => applyText('')}
          >
            <RotateCcw className="me-1 h-3 w-3" />
            {t('common.cvss.reset', 'Clear')}
          </Button>
        )}
      </div>

      {open && (
        <div className="grid grid-cols-1 gap-x-6 gap-y-4 md:grid-cols-2">
          {groups.map((g) => (
            <div key={g} className="space-y-2.5">
              <p className="text-xs font-medium text-muted-foreground">
                {t(`common.cvss.group.${g}`, GROUP_NAMES[g])}
              </p>
              {defs
                .filter((d) => d.group === g)
                .map((d) => (
                  <div key={d.key} className="space-y-1">
                    <p id={`cvss-${d.key}`} className="text-xs">
                      {t(`common.cvss.metric.${d.key}`, METRIC_NAMES[d.key])}{' '}
                      <span className="font-mono text-muted-foreground">({d.key})</span>
                    </p>
                    <div
                      role="radiogroup"
                      aria-labelledby={`cvss-${d.key}`}
                      className="flex flex-wrap gap-1"
                    >
                      {d.values.map((v) => {
                        const on = metrics[d.key] === v
                        return (
                          <button
                            key={v}
                            type="button"
                            role="radio"
                            aria-checked={on}
                            onClick={() => pick(d.key, v)}
                            className={cn(
                              'rounded-md border px-2 py-1 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                              on
                                ? 'border-primary bg-primary text-primary-foreground'
                                : 'bg-background text-muted-foreground hover:bg-muted hover:text-foreground'
                            )}
                          >
                            {valueName(d.key, v)}
                          </button>
                        )
                      })}
                    </div>
                  </div>
                ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
