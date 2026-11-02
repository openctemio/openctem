/**
 * Organization detection rule hooks: /api/v1/content-rules. Pass
 * `enabled: false` when the caller lacks scans:content:read so no request
 * (and no 403) is made. The API is the authority on every write.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'
import { del, get, patch, post } from '@/lib/api/client'
import { API_BASE, contentRuleEndpoints } from '@/lib/api/endpoints'

import type {
  ContentRule,
  ContentRuleList,
  ContentRuleSample,
  ContentRuleTestResult,
  DetectionRule,
  RuleKind,
} from '../types'

const defaultConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/** The organization's rules and the platform packs in use. */
export function useContentRules(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<ContentRuleList>(
    currentTenant && enabled ? contentRuleEndpoints.list() : null,
    (url: string) => get<ContentRuleList>(url),
    defaultConfig
  )
}

/** Revalidates every detection rule request, keeping the data on screen. */
export async function invalidateContentRules() {
  const { mutate } = await import('swr')
  await mutate((key) => typeof key === 'string' && key.startsWith(API_BASE.CONTENT_RULES))
}

export function createContentRule(body: {
  kind: RuleKind
  rule: DetectionRule
  enabled?: boolean
}) {
  return post<ContentRule>(contentRuleEndpoints.create(), body)
}

export function updateContentRule(id: string, body: { rule?: DetectionRule; enabled?: boolean }) {
  return patch<ContentRule>(contentRuleEndpoints.update(id), body)
}

export function deleteContentRule(id: string) {
  return del<void>(contentRuleEndpoints.delete(id))
}

export function testContentRule(body: {
  kind: RuleKind
  rule: DetectionRule
  sample: ContentRuleSample
}) {
  return post<ContentRuleTestResult>(contentRuleEndpoints.test(), body)
}
