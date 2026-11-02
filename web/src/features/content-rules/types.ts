/**
 * Organization detection rules: the wire shapes of /api/v1/content-rules
 * (api docs/architecture/rule-packs.md).
 */

export type RuleKind = 'web-fingerprints' | 'secret-rules'

export type MatcherLocation = 'body' | 'url' | 'title' | 'header' | 'cookie' | 'favicon' | 'script'

export interface RuleMatcher {
  location: MatcherLocation
  header?: string
  keywords?: string[]
  pattern?: string
  hashes?: string[]
}

export interface DetectionRule {
  id: string
  name: string
  description?: string
  condition?: 'any' | 'all'
  matchers: RuleMatcher[]
  technology?: { name: string; category?: string; cpe?: string }
  confidence?: number
  secret?: { category: string; severity: string }
}

export interface ContentRule {
  id: string
  kind: RuleKind
  rule_id: string
  name: string
  enabled: boolean
  /** Rises when the rule changes. */
  version: number
  sha256: string
  rule: DetectionRule
  created_at: string
  updated_at: string
}

export interface ContentRulePack {
  kind: RuleKind
  pack: string
  version: string
  digest: string
  rules: number
}

export interface ContentRuleList {
  items: ContentRule[]
  platform: ContentRulePack[]
  /** The most rules an organization may have. */
  limit: number
}

export interface ContentRuleSample {
  url?: string
  title?: string
  headers?: Record<string, string>
  cookies?: string[]
  body?: string
  scripts?: string[]
}

export interface ContentRuleTestResult {
  technologies: {
    rule_id: string
    name: string
    version: string
    category: string
    cpe: string
    confidence: number
  }[]
  /** Masked: a short preview, the length and where; never the value. */
  secrets: {
    rule_id: string
    category: string
    severity: string
    field: string
    line: number
    column: number
    preview: string
    length: number
  }[]
  truncated: boolean
  stopped: string
}
