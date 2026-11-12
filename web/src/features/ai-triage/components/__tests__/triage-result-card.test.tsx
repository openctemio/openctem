import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TriageResultCard } from '../triage-result-card'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi from '@/lib/i18n/dictionaries/vi/findings.json'
import type { AITriageResult } from '../../types'

const result = {
  id: 't1',
  status: 'completed',
  createdAt: '2026-11-01T00:00:00Z',
  summary: 'x',
  severityAssessment: 'high',
  riskScore: 70,
  priorityRank: 50,
  severityJustification: 'because',
  businessImpact: 'impact',
  remediationSteps: [{ step: 1, description: 'patch', effort: 'low' }],
  promptTokens: 10,
  completionTokens: 5,
} as unknown as AITriageResult

describe('TriageResultCard', () => {
  it('takes its text from the catalog', () => {
    render(<TriageResultCard result={result} />)
    expect(screen.getByText(en['findings.aiTriage.card.title'])).toBeInTheDocument()
    expect(screen.getByText(en['findings.aiTriage.card.riskScore'])).toBeInTheDocument()
    expect(screen.getByText(en['findings.aiTriage.card.remediationSteps'])).toBeInTheDocument()
    expect(screen.getByText('Tokens used: 10 input + 5 output = 15 total')).toBeInTheDocument()
  })

  it('has a Vietnamese value for every card key', () => {
    const keys = Object.keys(en).filter((k) => k.startsWith('findings.aiTriage.card.'))
    expect(keys.length).toBeGreaterThan(10)
    for (const k of keys) expect(vi).toHaveProperty([k])
  })
})
