'use client'

import { useCallback } from 'react'

import { useTranslation } from '@/context/i18n-provider'

import type { ClientKind, ConsentBlocked } from '../api/consent'

/** Host-name shape the API accepts for an approved publisher. */
const HOST_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/

/**
 * Normalizes what an administrator typed or pasted as a publisher: a host
 * name, or a URL whose host is taken. Returns null when it is not a host
 * name the API accepts (no wildcard, no single label, at most 253 chars).
 */
export function normalizePublisherHost(input: string): string | null {
  let h = input.trim().toLowerCase()
  if (!h) return null
  if (h.includes('://')) {
    try {
      h = new URL(h).hostname
    } catch {
      return null
    }
  }
  if (h.length > 253 || !HOST_RE.test(h)) return null
  return h
}

/** The comment-adding scope: a write scope, confirmed per call by the person. */
export const MCP_COMMENT_SCOPE = 'mcp:findings.comment'

/**
 * Words for MCP scopes, application identities and policy refusals, in the
 * person's language. Unknown scopes fall back to the server's title or the
 * scope id.
 */
export function useMcpLabels() {
  const { t } = useTranslation()

  /** Short name for a chip ("Findings"). */
  const scopeShort = useCallback(
    (scope: string): string => {
      switch (scope) {
        case 'mcp:findings.read':
          return t('mcp.scope.findings.short', 'Findings')
        case 'mcp:assets.read':
          return t('mcp.scope.assets.short', 'Assets')
        case 'mcp:compliance.read':
          return t('mcp.scope.compliance.short', 'Compliance')
        case 'mcp:pentest.read':
          return t('mcp.scope.pentest.short', 'Pentest')
        case MCP_COMMENT_SCOPE:
          return t('mcp.scope.comment.short', 'Comments')
        default:
          return scope
      }
    },
    [t]
  )

  /** What the scope lets an application do, in a sentence. */
  const scopeTitle = useCallback(
    (scope: string, fallback?: string): string => {
      switch (scope) {
        case 'mcp:findings.read':
          return t(
            'mcp.scope.findings.title',
            'Read findings, vulnerabilities, priorities and remediation groups'
          )
        case 'mcp:assets.read':
          return t('mcp.scope.assets.title', 'Read assets and attack paths')
        case 'mcp:compliance.read':
          return t('mcp.scope.compliance.title', 'Read compliance posture')
        case 'mcp:pentest.read':
          return t(
            'mcp.scope.pentest.title',
            'Read pentest campaigns, findings, retests and templates'
          )
        case MCP_COMMENT_SCOPE:
          return t(
            'mcp.scope.comment.title',
            'Add comments to findings, each one confirmed by you in {product}'
          )
        default:
          return fallback || scope
      }
    },
    [t]
  )

  /** How an application identifies itself. */
  const clientKind = useCallback(
    (kind: ClientKind, host?: string): string => {
      switch (kind) {
        case 'metadata_document':
          return host
            ? t('mcp.client.publishedBy', 'Published by {host}', { host })
            : t('mcp.client.publishedByProvider', 'Published by its provider')
        case 'organization':
          return t('mcp.client.registeredByOrg', 'Registered by your organization')
        default:
          return t('mcp.client.selfRegistered', 'Unverified: registered itself')
      }
    },
    [t]
  )

  /** Why the organization refuses an application. */
  const blockedMessage = useCallback(
    (b: ConsentBlocked, kind: ClientKind, host?: string): string => {
      if (b === 'mcp_disabled') {
        return t('mcp.consent.blocked.disabled', 'Your organization has turned off AI assistants.')
      }
      if (kind === 'metadata_document' && host) {
        return t(
          'mcp.consent.blocked.publisher',
          'Applications published by {host} need an administrator’s approval before anyone can connect them.',
          { host }
        )
      }
      return t(
        'mcp.consent.blocked.unverified',
        'Nobody vouches for this application. An administrator can only allow it by allowing unverified applications for the whole organization.'
      )
    },
    [t]
  )

  return { scopeShort, scopeTitle, clientKind, blockedMessage }
}
