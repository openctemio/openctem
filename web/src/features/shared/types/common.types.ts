/**
 * Common Types
 *
 * Shared type definitions used across features
 */

import {
  SEVERITY_DOT_COLORS,
  SEVERITY_SOLID_TEXT,
  SEVERITY_BORDER_COLORS,
  type SeverityLevel as SeverityColorLevel,
} from '@/lib/severity-colors'
import type { RatedCriticality } from '@/lib/criticality'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none'

export type Status =
  'active' | 'stale' | 'inactive' | 'archived' | 'pending' | 'completed' | 'failed'

export type Environment = 'production' | 'staging' | 'development' | 'testing'

/** Criticality of always-rated records (groups); assets use CriticalityLevel. */
export type Criticality = RatedCriticality

// Security Process Steps
export type SecurityProcessStep =
  'scoping' | 'discovery' | 'prioritization' | 'validation' | 'mobilization'

export const SECURITY_PROCESS_STEPS: {
  id: SecurityProcessStep
  label: string
  description: string
}[] = [
  { id: 'scoping', label: 'Scoping', description: 'Define attack surface' },
  {
    id: 'discovery',
    label: 'Discovery',
    description: 'Find assets & threats',
  },
  {
    id: 'prioritization',
    label: 'Prioritization',
    description: 'Risk analysis',
  },
  { id: 'validation', label: 'Validation', description: 'Simulate attacks' },
  { id: 'mobilization', label: 'Mobilization', description: 'Remediate' },
]

// Severity configuration for UI. Colors are DERIVED from the single source of
// truth (src/lib/severity-colors.ts) so this map can never drift from it — the
// values are identical to the previous hard-coded ones (no visual change).
const sevEntry = (label: string, level: SeverityColorLevel) => ({
  label,
  color: SEVERITY_DOT_COLORS[level],
  textColor: SEVERITY_SOLID_TEXT[level],
  borderColor: SEVERITY_BORDER_COLORS[level],
})

export const SEVERITY_CONFIG = {
  critical: sevEntry('Critical', 'critical'),
  high: sevEntry('High', 'high'),
  medium: sevEntry('Medium', 'medium'),
  low: sevEntry('Low', 'low'),
  info: sevEntry('Info', 'info'),
  // "none" (CVSS 0.0) reads and looks like Info, as everywhere else.
  none: sevEntry('Info', 'info'),
} as const

// Risk level thresholds interface
export interface RiskLevelThresholds {
  critical_min: number
  high_min: number
  medium_min: number
  low_min: number
}

// Default risk level thresholds
export const DEFAULT_RISK_LEVELS: RiskLevelThresholds = {
  critical_min: 80,
  high_min: 60,
  medium_min: 40,
  low_min: 20,
}

// Risk level configuration — supports optional custom thresholds
/** Risk level band key; the label is `t(\`riskScore.level.${key}\`)`. */
export type RiskLevelKey = 'critical' | 'high' | 'medium' | 'low' | 'minimal' | 'none'

/**
 * The band of a 0-100 risk score, from the organization's risk levels (the
 * same bands the API uses): critical/high/medium/low from their lower bounds,
 * minimal above 0 and below the low bound, none at 0 (no open risk).
 * `label` is the English fallback of `riskScore.level.<key>`.
 */
export const getRiskLevel = (score: number, thresholds?: RiskLevelThresholds) => {
  const t = thresholds ?? DEFAULT_RISK_LEVELS
  if (score >= t.critical_min)
    return {
      key: 'critical' as RiskLevelKey,
      label: 'Critical',
      color: 'bg-red-500', // palette-ok: risk band fill, also mapped to stroke- and bar colours
      textColor: 'text-white',
    }
  if (score >= t.high_min)
    return {
      key: 'high' as RiskLevelKey,
      label: 'High',
      color: 'bg-orange-500', // palette-ok: risk band fill, also mapped to stroke- and bar colours
      textColor: 'text-white',
    }
  if (score >= t.medium_min)
    return {
      key: 'medium' as RiskLevelKey,
      label: 'Medium',
      color: 'bg-yellow-500', // palette-ok: risk band fill, also mapped to stroke- and bar colours
      textColor: 'text-black',
    }
  if (score >= t.low_min)
    return {
      key: 'low' as RiskLevelKey,
      label: 'Low',
      color: 'bg-blue-500', // palette-ok: risk band fill, also mapped to stroke- and bar colours
      textColor: 'text-white',
    }
  if (score > 0)
    return {
      key: 'minimal' as RiskLevelKey,
      label: 'Minimal',
      color: 'bg-green-500', // palette-ok: risk band fill, also mapped to stroke- and bar colours
      textColor: 'text-white',
    }
  return {
    key: 'none' as RiskLevelKey,
    label: 'No open risk',
    color: 'bg-green-500', // palette-ok: risk band fill, also mapped to stroke- and bar colours
    textColor: 'text-white',
  }
}

// ============================================
// Org / asset risk score (single source of truth)
// ============================================
//
// Risk scores across the platform are on a 0–100 scale — matching the
// asset-stats `risk_score_avg` and the executive-summary `risk_score_current`
// the backend computes as AVG(assets.risk_score). Every "Risk Score" surface
// (StatsCards, hero cards, gauges) MUST render through these helpers so the
// value, scale, and level label stay identical across pages. Do NOT hand-roll
// a `/ 10` label or a private threshold ladder.

/** Maximum value of the canonical risk-score scale. */
export const RISK_SCORE_MAX = 100

/**
 * Format a 0–100 risk score for display, e.g. `formatRiskScore(52.7)` → "52.7 / 100".
 * Clamps out-of-range inputs so a stray 0–100 value never renders on a wrong axis.
 */
export function formatRiskScore(score: number, fractionDigits = 1): string {
  const clamped = Math.max(0, Math.min(RISK_SCORE_MAX, score))
  return `${clamped.toFixed(fractionDigits)} / ${RISK_SCORE_MAX}`
}

/** Tailwind text-color class for a 0–100 risk score, aligned with getRiskLevel bands. */
export function getRiskScoreTextColor(score: number, thresholds?: RiskLevelThresholds): string {
  const t = thresholds ?? DEFAULT_RISK_LEVELS
  if (score >= t.critical_min) return 'text-red-500'
  if (score >= t.high_min) return 'text-orange-500'
  if (score >= t.medium_min) return 'text-yellow-500'
  if (score >= t.low_min) return 'text-blue-500'
  return 'text-green-500'
}

/** StatsCard `changeType` for a 0–100 risk score (higher = worse). */
export function getRiskScoreChangeType(
  score: number,
  thresholds?: RiskLevelThresholds
): 'positive' | 'neutral' | 'negative' {
  const t = thresholds ?? DEFAULT_RISK_LEVELS
  if (score >= t.high_min) return 'negative'
  if (score >= t.medium_min) return 'neutral'
  return 'positive'
}

// User types
export type UserRole =
  | 'admin'
  | 'security_analyst'
  | 'security_engineer'
  | 'soc_manager'
  | 'penetration_tester'
  | 'ciso'
  | 'viewer'

export interface User {
  id: string
  name: string
  email: string
  role: UserRole
  avatar?: string
  department?: string
  isActive: boolean
  lastLoginAt?: string
  createdAt: string
  updatedAt: string
}

export const USER_ROLE_LABELS: Record<UserRole, string> = {
  admin: 'Administrator',
  security_analyst: 'Security Analyst',
  security_engineer: 'Security Engineer',
  soc_manager: 'SOC Manager',
  penetration_tester: 'Penetration Tester',
  ciso: 'CISO',
  viewer: 'Viewer',
}
