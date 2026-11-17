'use client'

import { Info, Plus } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { ApiClientError } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsBlock, SettingsField, SettingsSection } from '@/features/shared'
import type { ReactNode } from 'react'

/** "a\n b \n\nc" -> ["a", "b", "c"] */
export function parseLines(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
}

/**
 * The API refuses an IP allowlist that would lock the caller out:
 * 400 "IP allowlist must include your current IP address (<ip>)".
 */
export function isIpLockoutError(err: unknown): err is ApiClientError {
  return (
    err instanceof ApiClientError &&
    err.statusCode === 400 &&
    /ip allowlist must include your current ip/i.test(err.message)
  )
}

export interface NetworkRestrictionSectionProps {
  /** One entry per line. */
  ipAllowlist: string
  onIpAllowlistChange: (value: string) => void
  /** The caller's IP as the API sees it (GET /settings → security.current_ip). */
  currentIp?: string
  /** Inline error for the IP allowlist (e.g. the lockout refusal). */
  ipAllowlistError?: string | null
  disabled?: boolean
  /** "Last changed by …" at the end of the heading row. */
  meta?: ReactNode
}

/**
 * The networks users may reach the organization from (the API enforces it for
 * user accounts only). Sign-in tab of Settings › Sign-in.
 */
export function NetworkRestrictionSection({
  ipAllowlist,
  onIpAllowlistChange,
  currentIp,
  ipAllowlistError,
  disabled,
  meta,
}: NetworkRestrictionSectionProps) {
  const { t } = useTranslation()
  const ipEntries = parseLines(ipAllowlist)
  const currentIpListed = !!currentIp && ipEntries.includes(currentIp)

  return (
    <SettingsSection
      framed
      id="network-restriction"
      title={t('org.access.networkTitle', 'Network restriction')}
      description={t(
        'org.access.desc',
        'Enforced for user accounts in this organization. Sensors, API keys and the platform admin console are not affected.'
      )}
      meta={meta}
    >
      <SettingsBlock id="ip-allowlist">
        <SettingsField
          id="ip-whitelist"
          label={t('org.access.ip', 'IP allowlist')}
          error={
            ipAllowlistError ? (
              <>
                {ipAllowlistError}{' '}
                {t(
                  'org.access.lockout',
                  'Saving it would lock you out. Include your current IP (or a range containing it), or leave the list empty.'
                )}
              </>
            ) : undefined
          }
          hint={
            <>
              {t(
                'org.access.ipHelp',
                'When set, users can only use this organization from these addresses; requests from anywhere else are refused. The check uses the IP address the server sees: behind a VPN, proxy or NAT that is the address of that gateway, not your device.'
              )}
              {ipEntries.length === 0 && (
                <>
                  {' '}
                  <span className="font-medium text-foreground">
                    {t('org.access.ipEmpty', 'Empty: no IP restriction.')}
                  </span>
                </>
              )}
            </>
          }
        >
          {(control) => (
            <Textarea
              {...control}
              placeholder={t(
                'org.access.ipPlaceholder',
                'IP addresses or CIDR ranges, one per line\nExample: 192.168.1.0/24'
              )}
              value={ipAllowlist}
              onChange={(e) => onIpAllowlistChange(e.target.value)}
              rows={4}
              disabled={disabled}
              className="font-mono"
            />
          )}
        </SettingsField>

        {currentIp && (
          <div className="flex flex-wrap items-center gap-2 text-dense">
            <Info className="size-4 text-muted-foreground" aria-hidden />
            <span className="text-muted-foreground">
              {t('org.access.currentIp', 'Your current IP:')}
            </span>
            <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-cap">{currentIp}</code>
            {!currentIpListed && !disabled && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() =>
                  onIpAllowlistChange(
                    ipAllowlist.trim() ? `${ipAllowlist.trimEnd()}\n${currentIp}` : currentIp
                  )
                }
              >
                <Plus aria-hidden />
                {t('org.access.addMyIp', 'Add my IP')}
              </Button>
            )}
          </div>
        )}
      </SettingsBlock>
    </SettingsSection>
  )
}

export interface AllowedDomainsBlockProps {
  /** One domain per line. */
  allowedDomains: string
  onAllowedDomainsChange: (value: string) => void
  disabled?: boolean
}

/** The extra email domains that may join (Joining tab, "Who may join"). */
export function AllowedDomainsBlock({
  allowedDomains,
  onAllowedDomainsChange,
  disabled,
}: AllowedDomainsBlockProps) {
  const { t } = useTranslation()
  const domainEntries = parseLines(allowedDomains)
  return (
    <SettingsBlock id="allowed-domains">
      <SettingsField
        id="allowed-domains-input"
        label={t('org.access.domains', 'Allowed email domains')}
        hint={
          <>
            {t(
              'org.access.domainsHelp',
              'When set, only people whose email is at one of these domains can be invited, added by an administrator, or join through single sign-on. Existing members are not removed.'
            )}
            {domainEntries.length === 0 && (
              <>
                {' '}
                <span className="font-medium text-foreground">
                  {t('org.access.domainsEmpty', 'Empty: any email domain is allowed.')}
                </span>
              </>
            )}
          </>
        }
      >
        {(control) => (
          <Textarea
            {...control}
            placeholder={t(
              'org.access.domainsPlaceholder',
              'One domain per line\nExample: example.com'
            )}
            value={allowedDomains}
            onChange={(e) => onAllowedDomainsChange(e.target.value)}
            rows={3}
            disabled={disabled}
            className="font-mono"
          />
        )}
      </SettingsField>
    </SettingsBlock>
  )
}
