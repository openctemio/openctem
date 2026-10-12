/**
 * Credential API Mapper
 *
 * Maps API response to frontend types for compatibility with existing UI components
 */

import type { ApiCredential, ApiCredentialStats } from '../api/credential-api.types'
import type { Asset } from '@/features/assets'
import type { Status } from '@/features/shared/types'
import { severityCounts } from '@/lib/severity'

// Map API state to frontend status
const stateToStatus: Record<string, Status> = {
  active: 'active',
  resolved: 'completed',
  accepted: 'inactive',
  false_positive: 'inactive',
}

// Map API severity to risk score
const severityToRiskScore: Record<string, number> = {
  critical: 95,
  high: 80,
  medium: 55,
  low: 30,
  info: 10,
}

/**
 * What the credential list shows about one leak. These are fields of the
 * credential-leak API, not asset properties, so they have a type of their
 * own instead of riding on an asset's property schema.
 */
export interface CredentialLeakDetails {
  source: string
  username: string
  leakDate: string
  hasSecret: boolean
  secretMasked?: string
  secretFingerprint?: string
  credentialType: string
}

/** A credential leak shaped like an asset row, so the shared table components render it. */
export type CredentialLeakRow = Omit<Asset, 'metadata'> & { metadata: CredentialLeakDetails }

/**
 * Map API credential to an asset-shaped row for the shared table components.
 */
export function mapCredentialToAsset(credential: ApiCredential): CredentialLeakRow {
  const details = credential.details || {}

  // Extract context from details
  const username = (details.username as string) || ''
  const email = (details.email as string) || ''

  // Determine credential type display name
  const credTypeMap: Record<string, string> = {
    password: 'Password',
    api_key: 'API Key',
    oauth_token: 'OAuth Token',
    ssh_key: 'SSH Key',
    private_key: 'Private Key',
    database_cred: 'Database Credential',
    cloud_cred: 'Cloud Credential',
    session_token: 'Session Token',
    jwt_token: 'JWT Token',
    certificate: 'Certificate',
    other: 'Other',
  }

  // Every field on the generated wire type is optional: swag emits no `required`
  // list for response structs, so the contract says any of these may be absent.
  // The Asset view model requires them, so defaults belong here rather than in a
  // hand-written type that simply asserted they are always present.
  const credType = credential.credential_type ?? ''
  const source = credential.source ?? ''
  const severity = credential.severity ?? ''
  const state = credential.state ?? ''
  const firstSeen = credential.first_seen_at ?? ''
  const lastSeen = credential.last_seen_at ?? ''

  return {
    id: credential.id ?? '',
    type: 'credential',
    name: credential.identifier ?? '',
    description: `${credType} from ${source}`,
    criticality: severity === 'critical' || severity === 'high' ? 'critical' : 'high',
    status: stateToStatus[state] || 'active',
    scope: 'internal',
    exposure: 'public',
    riskScore: severityToRiskScore[severity] || 50,
    findingCount: 1,
    metadata: {
      source,
      username: username || email,
      leakDate: firstSeen.split('T')[0] || '',
      // The API never returns the plaintext: only a mask and a keyed
      // fingerprint. The plaintext comes from POST /credentials/{id}/reveal.
      hasSecret: credential.has_secret ?? false,
      secretMasked: credential.secret_masked,
      secretFingerprint: credential.secret_fingerprint,
      credentialType: credTypeMap[credType] || credType,
    },
    tags: [],
    firstSeen,
    lastSeen,
    createdAt: firstSeen,
    updatedAt: lastSeen,
  }
}

/**
 * Map multiple API credentials to Assets
 */
export function mapCredentialsToAssets(credentials: ApiCredential[]): CredentialLeakRow[] {
  return credentials.map(mapCredentialToAsset)
}

/**
 * Extract stats from API response
 */
export function extractCredentialStats(stats: ApiCredentialStats | undefined) {
  if (!stats) {
    return {
      total: 0,
      active: 0,
      resolved: 0,
      accepted: 0,
      falsePositive: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
  }

  return {
    total: stats.total,
    active: stats.by_state?.active || 0,
    resolved: stats.by_state?.resolved || 0,
    accepted: stats.by_state?.accepted || 0,
    falsePositive: stats.by_state?.false_positive || 0,
    ...severityCounts(stats.by_severity),
  }
}
