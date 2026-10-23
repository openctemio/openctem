'use client'

import { Copy, Database, ExternalLink, Globe, Key, Server } from 'lucide-react'
import { toast } from 'sonner'

import { SafeExternalLink } from '@/components/safe-external-link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { LeakedSecretField } from '@/features/credentials'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'

/**
 * The API masks every tool-reported secret in exposure details (password,
 * token, key, secret_*) before it leaves the server, so the browser never holds
 * the raw value and there is nothing to reveal here. A leaked credential's
 * plaintext is revealed on demand through LeakedSecretField (audited endpoint).
 */
export const REDACTED_VALUE = '********'

/** `source_url` → `Source url` when there is no explicit label. */
function humanizeKey(key: string): string {
  const text = key.replace(/_/g, ' ')
  return text.charAt(0).toUpperCase() + text.slice(1)
}

// A leaked credential's secret is served only as a mask and a keyed
// fingerprint; both are rendered by LeakedSecretField, not in the grid.
const LEAKED_SECRET_FIELDS = ['secret_value', 'secret_masked', 'secret_fingerprint']

// Field labels mapping
const FIELD_LABELS: Record<string, string> = {
  credential_type: 'Type',
  source_type: 'Source type',
  source_url: 'Source URL',
  source_name: 'Source',
  database_host: 'Host',
  database_name: 'Database',
  database_port: 'Port',
  database_type: 'Type',
  username: 'Username',
  email: 'Email',
  domain: 'Domain',
  identifier: 'Identifier',
  ip_address: 'IP address',
  file_path: 'File',
  repository: 'Repository',
  commit_hash: 'Commit',
  branch: 'Branch',
  line_number: 'Line',
  breach_name: 'Breach',
  breach_date: 'Date',
  is_verified: 'Verified',
  is_revoked: 'Revoked',
  discovered_at: 'Discovered',
  classification: 'Classification',
}

// Group fields by category
const FIELD_GROUPS: Record<string, { title: string; icon: typeof Key; fields: string[] }> = {
  credential: {
    title: 'Credential',
    icon: Key,
    fields: ['credential_type', 'identifier', 'username', 'email', 'is_verified', 'is_revoked'],
  },
  database: {
    title: 'Database',
    icon: Database,
    fields: ['database_host', 'database_name', 'database_port', 'database_type'],
  },
  source: {
    title: 'Source',
    icon: Globe,
    fields: [
      'source_type',
      'source_name',
      'source_url',
      'breach_name',
      'breach_date',
      'discovered_at',
    ],
  },
  code: {
    title: 'Code location',
    icon: Server,
    fields: ['repository', 'file_path', 'branch', 'commit_hash', 'line_number'],
  },
  network: {
    title: 'Network',
    icon: Globe,
    fields: ['domain', 'ip_address'],
  },
}

interface ExposureDetailsViewProps {
  details: Record<string, unknown>
  /** Set for a credential_leaked exposure: its id doubles as the credential id. */
  leakedCredentialId?: string
}

function isUrl(value: string): boolean {
  return value.startsWith('http://') || value.startsWith('https://')
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '-'
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function DetailRow({ label, value }: { label: string; value: unknown }) {
  const { t } = useTranslation()
  const stringValue = formatValue(value)
  const masked = stringValue === REDACTED_VALUE
  const showAsUrl = !masked && isUrl(stringValue)
  const handleCopy = () => {
    copyToClipboard(stringValue)
    toast.success(t('exposures.details.copied'))
  }

  return (
    <div className="flex items-center justify-between px-3 py-2 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        {showAsUrl ? (
          <SafeExternalLink
            href={stringValue}
            className="text-primary hover:underline flex items-center gap-1 max-w-[200px] truncate"
          >
            {stringValue}
            <ExternalLink className="h-3 w-3 flex-shrink-0" />
          </SafeExternalLink>
        ) : (
          <span
            className={cn('font-mono text-xs max-w-[200px] truncate', masked && 'text-destructive')}
          >
            {stringValue}
          </span>
        )}
        {!masked && stringValue !== '-' && (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            aria-label={t('exposures.details.copy')}
            onClick={handleCopy}
          >
            <Copy className="h-3 w-3" />
          </Button>
        )}
      </div>
    </div>
  )
}

export function ExposureDetailsView({
  details: rawDetails,
  leakedCredentialId,
}: ExposureDetailsViewProps) {
  const { t } = useTranslation()
  const leakedSecret = {
    masked: typeof rawDetails.secret_masked === 'string' ? rawDetails.secret_masked : undefined,
    fingerprint:
      typeof rawDetails.secret_fingerprint === 'string' ? rawDetails.secret_fingerprint : undefined,
  }
  const hasLeakedSecret = Boolean(leakedSecret.masked || leakedSecret.fingerprint)
  const details = Object.fromEntries(
    Object.entries(rawDetails).filter(([key]) => !LEAKED_SECRET_FIELDS.includes(key))
  )

  const groupedDetails: Record<string, { key: string; value: unknown }[]> = {}
  const ungroupedDetails: { key: string; value: unknown }[] = []
  Object.entries(details).forEach(([key, value]) => {
    if (value === null || value === undefined || value === '') return
    const groupKey = Object.keys(FIELD_GROUPS).find((g) => FIELD_GROUPS[g].fields.includes(key))
    if (groupKey) {
      ;(groupedDetails[groupKey] ??= []).push({ key, value })
    } else {
      ungroupedDetails.push({ key, value })
    }
  })

  return (
    <div className="space-y-4">
      {leakedCredentialId && hasLeakedSecret && (
        <LeakedSecretField
          credentialId={leakedCredentialId}
          hasSecret
          masked={leakedSecret.masked}
          fingerprint={leakedSecret.fingerprint}
          showWarning={false}
        />
      )}
      <h4 className="text-sm font-medium">{t('exposures.details.title')}</h4>

      {Object.entries(FIELD_GROUPS).map(([groupKey, group]) => {
        const groupItems = groupedDetails[groupKey]
        if (!groupItems || groupItems.length === 0) return null
        const GroupIcon = group.icon
        return (
          <div key={groupKey} className="rounded-lg border">
            <div className="flex items-center gap-2 px-3 py-2 bg-muted/50 border-b">
              <GroupIcon className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">{group.title}</span>
            </div>
            <div className="divide-y">
              {groupItems.map(({ key, value }) => (
                <DetailRow key={key} label={FIELD_LABELS[key] || humanizeKey(key)} value={value} />
              ))}
            </div>
          </div>
        )
      })}

      {ungroupedDetails.length > 0 && (
        <div className="rounded-lg border">
          <div className="flex items-center gap-2 px-3 py-2 bg-muted/50 border-b">
            <span className="text-sm font-medium">{t('exposures.details.additional')}</span>
          </div>
          <div className="divide-y">
            {ungroupedDetails.map(({ key, value }) => (
              <DetailRow key={key} label={FIELD_LABELS[key] || humanizeKey(key)} value={value} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
