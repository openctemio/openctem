'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from '@/components/link'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  DetailDisclosure,
  SettingsBlock,
  SettingsField,
  SettingsPage,
  SettingsRow,
  SettingsSaveBar,
  SettingsSection,
} from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { useTenant } from '@/context/tenant-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'
import {
  useTenantSettings,
  useUpdateSecuritySettings,
} from '@/features/organization/api/use-tenant-settings'
import { LastChanged } from '@/features/organization/components/last-changed'
import {
  MAX_ORGANIZATION_HEADERS,
  MAX_USER_AGENT,
  headerListErrors,
  mergeIdentity,
  normalizeHeaders,
  normalizeQuery,
  parseUserAgentList,
  queryError,
  requiredWithoutMarker,
  userAgentBothError,
  userAgentError,
  userAgentListErrors,
  type IdentHeader,
  type IdentQuery,
} from '../lib/scan-identification'
import {
  HeaderListEditor,
  IdentityPreview,
  QueryParamFields,
  RequiredMissingAlert,
  UserAgentRotationField,
  useIdentSourceLabel,
} from './scan-identification-parts'

export const SCAN_IDENT_FIELDS = [
  'tool_http_user_agent',
  'tool_http_user_agents',
  'tool_http_headers',
  'tool_http_query',
  'tool_http_identification_required',
] as const

interface Form {
  userAgent: string
  /** The rotation list as typed: one value per line. */
  userAgents: string
  headers: IdentHeader[]
  query: IdentQuery
  required: boolean
}

const EMPTY_QUERY: IdentQuery = { name: '', value: '' }

/** What the form saves, normalized as the API stores it. */
function normalizedForm(f: Form) {
  return {
    userAgent: f.userAgent.trim(),
    userAgents: parseUserAgentList(f.userAgents),
    headers: normalizeHeaders(f.headers),
    query: normalizeQuery(f.query),
    required: f.required,
  }
}

/**
 * Settings › Scanning › Scan identification: the User-Agent (or a rotation
 * list), request headers and query parameter the organization's scan tools
 * send, so the scanned systems' WAF, SIEM and logs recognize its scans, and
 * the one main switch: require identification on every request. Part of the security settings section
 * (owner only, recent sign-in). The platform's layer is shown read-only; the
 * preview is the merge the platform makes for every job.
 */
export function ScanIdentificationSettings() {
  const { t } = useTranslation()
  const { currentTenant } = useTenant()
  const tenantId = currentTenant?.id
  const canEdit = useCanMutate('PATCH /api/v1/tenants/{tenant}/settings/security')
  const { settings, isLoading, isError, error, mutate } = useTenantSettings(tenantId)
  const { updateSecuritySettings, isUpdating } = useUpdateSecuritySettings(tenantId)

  const sourceLabel = useIdentSourceLabel()
  const saved = useMemo<Form>(
    () => ({
      userAgent: settings?.security?.tool_http_user_agent ?? '',
      userAgents: (settings?.security?.tool_http_user_agents ?? []).join('\n'),
      headers: settings?.security?.tool_http_headers ?? [],
      query: settings?.security?.tool_http_query ?? EMPTY_QUERY,
      required: !!settings?.security?.tool_http_identification_required,
    }),
    [settings]
  )
  const platform = settings?.security?.platform_scan_identification
  const [form, setForm] = useState<Form>(saved)
  const [saveError, setSaveError] = useState(false)
  const reset = useCallback(() => {
    setForm(saved)
    setSaveError(false)
  }, [saved])
  useEffect(() => {
    reset()
  }, [reset])

  const next = normalizedForm(form)
  const uaError =
    userAgentError(form.userAgent, t) ?? userAgentBothError(form.userAgent, next.userAgents, t)
  const rotationInvalid = userAgentListErrors(form.userAgents, t).length > 0
  const qError = queryError(form.query, t)
  const listInvalid = Object.keys(headerListErrors(form.headers, t)).length > 0
  const invalid = !!uaError || rotationInvalid || !!qError || listInvalid
  const dirty = JSON.stringify(next) !== JSON.stringify(normalizedForm(saved))
  const identity = mergeIdentity(platform, {
    userAgent: next.userAgent,
    userAgents: next.userAgents,
    headers: form.headers,
    query: next.query,
    required: form.required,
  })
  const missingMarker = requiredWithoutMarker(identity)
  const uaLocked = !!platform?.user_agent_enforced
  const queryLocked = !!platform?.query_enforced && !!platform?.query

  const addHeader = () => {
    setForm((f) => ({ ...f, headers: [...f.headers, { name: '', value: '' }] }))
    const idx = form.headers.length
    requestAnimationFrame(() => document.getElementById(`scan-ident-name-${idx}`)?.focus())
  }

  const savedNext = normalizedForm(saved)
  const changes = [
    next.required !== savedNext.required &&
      t('sensors.scanIdent.required.label', 'Require identification on every request'),
    next.userAgent !== savedNext.userAgent &&
      t('sensors.httpPolicy.ua.label', 'User-Agent of scan tools'),
    JSON.stringify(next.headers) !== JSON.stringify(savedNext.headers) &&
      t('sensors.scanIdent.headers', 'Request headers'),
    JSON.stringify(next.userAgents) !== JSON.stringify(savedNext.userAgents) &&
      t('sensors.scanIdent.rotation.label', 'User-Agent rotation'),
    JSON.stringify(next.query) !== JSON.stringify(savedNext.query) &&
      t('sensors.scanIdent.query.label', 'Query parameter'),
  ].filter((c): c is string => typeof c === 'string')

  const save = async () => {
    if (invalid) return
    setSaveError(false)
    try {
      const result = await updateSecuritySettings({
        tool_http_user_agent: next.userAgent,
        tool_http_user_agents: next.userAgents,
        tool_http_headers: next.headers,
        // A blank name and value clear the parameter.
        tool_http_query: next.query ?? EMPTY_QUERY,
        tool_http_identification_required: next.required,
      })
      if (result) await mutate(result, { revalidate: false })
      toast.success(t('sensors.scanIdent.saved', 'Scan identification saved'))
    } catch (err) {
      setSaveError(true)
      toast.error(
        getErrorMessage(
          err,
          t('sensors.scanIdent.saveFailed', 'Could not save the scan identification')
        )
      )
    }
  }

  const title = t('settings.item.scan-identification', 'Scan identification')
  const description = t(
    'sensors.scanIdent.desc',
    'Mark your scan traffic so the WAF, SIEM and logs of the scanned systems can tell it apart from other traffic.'
  )
  if (isLoading || isError) {
    return (
      <SettingsPage
        title={title}
        description={description}
        state={isError ? 'error' : 'loading'}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  const disabled = !canEdit
  const platformHeaders = platform?.headers ?? []
  const requiredLockedBy = platform?.identification_required
    ? t('sensors.scanIdent.required.byPlatform', 'the platform')
    : undefined

  return (
    <SettingsPage
      title={title}
      description={description}
      readOnly={
        disabled &&
        t('org.auth.ownerOnly', 'Only the organization owner can change these settings.')
      }
    >
      <SettingsSection
        framed
        id="scan-ident-rule"
        title={t('sensors.scanIdent.ruleTitle', 'Rule')}
        description={t(
          'sensors.scanIdent.ruleDesc',
          'Whether a request may leave without your markers.'
        )}
        meta={
          <LastChanged resourceType="tenant" resourceId={tenantId} fields={SCAN_IDENT_FIELDS} />
        }
      >
        <div data-testid="scan-ident-required-required">
          <SettingsRow
            label={
              <label htmlFor="scan-ident-required">
                {t('sensors.scanIdent.required.label', 'Require identification on every request')}
              </label>
            }
            hintId="scan-ident-required-desc"
            hint={
              <>
                {t(
                  'sensors.scanIdent.required.help',
                  'Tools that cannot carry the headers or query parameter are skipped with a reason; nothing is sent without them.'
                )}
                {requiredLockedBy && (
                  <span className="block">
                    {t('sensors.scanIdent.required.lockedBy', 'Required by: {source}', {
                      source: requiredLockedBy,
                    })}
                  </span>
                )}
              </>
            }
          >
            <Switch
              id="scan-ident-required"
              aria-describedby="scan-ident-required-desc"
              checked={form.required || !!requiredLockedBy}
              onCheckedChange={(required) => setForm((f) => ({ ...f, required }))}
              disabled={disabled || !!requiredLockedBy}
            />
          </SettingsRow>
        </div>
        {missingMarker && (
          <SettingsBlock>
            <RequiredMissingAlert onAddHeader={disabled ? undefined : addHeader} />
          </SettingsBlock>
        )}
      </SettingsSection>
      <SettingsSection
        framed
        id="scan-ident-markers"
        title={t('sensors.scanIdent.markers', 'What your scans send')}
        description={t(
          'sensors.scanIdent.markersDesc',
          'Sent on every HTTP request of every scan, retest and validation. Saved together with Save changes.'
        )}
      >
        <SettingsBlock id="user-agent">
          <SettingsField
            id="scan-ident-ua"
            label={t('sensors.httpPolicy.ua.label', 'User-Agent of scan tools')}
            hint={t('sensors.httpPolicy.ua.help')}
            error={uaError}
          >
            {(control) => (
              <Input
                {...control}
                placeholder={t(
                  'sensors.scanIdent.uaPlaceholder',
                  'acme-security-scan (+soc@acme.example)'
                )}
                value={form.userAgent}
                maxLength={MAX_USER_AGENT}
                onChange={(e) => setForm((f) => ({ ...f, userAgent: e.target.value }))}
                disabled={disabled || uaLocked}
              />
            )}
          </SettingsField>
          {platform?.user_agent && (
            <p className="text-cap text-muted-foreground">
              {platform.user_agent_enforced
                ? t('sensors.scanIdent.uaEnforced', 'The platform sets the User-Agent:')
                : t(
                    'sensors.scanIdent.uaDefault',
                    'Platform default, used while this is empty:'
                  )}{' '}
              <span className="break-all font-mono">{platform.user_agent}</span>
            </p>
          )}
          {(platform?.user_agents?.length ?? 0) > 0 && (
            <p className="text-cap text-muted-foreground">
              {platform?.user_agent_enforced
                ? t(
                    'sensors.scanIdent.listEnforced',
                    'The platform enforces a rotation list of {n} User-Agents.',
                    { n: platform?.user_agents?.length ?? 0 }
                  )
                : t(
                    'sensors.scanIdent.listDefault',
                    'Platform default: a rotation list of {n} User-Agents, used while yours is empty.',
                    { n: platform?.user_agents?.length ?? 0 }
                  )}
            </p>
          )}
        </SettingsBlock>
        <SettingsBlock id="headers">
          <div>
            <label htmlFor="scan-ident-name-0" className="text-dense font-medium">
              {t('sensors.scanIdent.headers', 'Request headers')}
            </label>
            <p className="text-cap text-muted-foreground text-pretty">
              {t(
                'sensors.scanIdent.headersHelp',
                'Any name and value, for example ATTT: is-here. Names are not case-sensitive. Connection, proxy, Host, Authorization and Cookie headers cannot be set.'
              )}
            </p>
          </div>
          <HeaderListEditor
            idPrefix="scan-ident"
            headers={form.headers}
            onChange={(headers) => setForm((f) => ({ ...f, headers }))}
            max={MAX_ORGANIZATION_HEADERS}
            disabled={disabled}
          />
          {platformHeaders.length > 0 && (
            <div className="space-y-2" data-testid="scan-ident-platform-headers">
              <p className="text-dense font-medium">
                {t('sensors.scanIdent.platformHeaders', 'Set by the platform')}
              </p>
              <ul className="space-y-1 text-dense">
                {platformHeaders.map((h) => (
                  <li key={h.name} className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="min-w-0 break-all font-mono">
                      {h.name}: {h.value}
                    </span>
                    <Badge variant="secondary">
                      {h.enforced
                        ? t('sensors.scanIdent.enforced', 'Enforced')
                        : t('sensors.scanIdent.default', 'Default, yours replaces it')}
                    </Badge>
                  </li>
                ))}
              </ul>
              {identity.overridden.length > 0 && (
                <p className="text-cap font-medium text-destructive">
                  {t(
                    'sensors.scanIdent.overridden',
                    'The platform enforces {names}; your value for it is not sent.',
                    { names: identity.overridden.join(', ') }
                  )}
                </p>
              )}
            </div>
          )}
        </SettingsBlock>
        <SettingsBlock id="advanced">
          <DetailDisclosure
            summary={t(
              'sensors.scanIdent.advanced',
              'Advanced: User-Agent rotation and query parameter'
            )}
          >
            <div className="mt-4 space-y-6">
              <UserAgentRotationField
                id="scan-ident-rotation"
                text={form.userAgents}
                onChange={(userAgents) => setForm((f) => ({ ...f, userAgents }))}
                disabled={disabled || uaLocked}
              />
              <QueryParamFields
                idPrefix="scan-ident"
                value={form.query}
                onChange={(query) => setForm((f) => ({ ...f, query }))}
                disabled={disabled || queryLocked}
              />
              {platform?.query && (
                <p className="text-cap text-muted-foreground">
                  {sourceLabel(platform.query_enforced ? 'platform_enforced' : 'platform')}:{' '}
                  <span className="break-all font-mono">
                    ?{platform.query.name}={platform.query.value}
                  </span>
                </p>
              )}
            </div>
          </DetailDisclosure>
        </SettingsBlock>
      </SettingsSection>
      <SettingsSection
        framed
        id="preview"
        title={t('sensors.scanIdent.preview', 'What a target receives')}
      >
        <SettingsBlock>
          <IdentityPreview identity={identity} />
        </SettingsBlock>
        <SettingsBlock>
          <p className="text-cap text-muted-foreground text-pretty">
            {t(
              'sensors.scanIdent.addressesHint',
              'Anyone who learns a header can send it. To let scans through a WAF, combine the headers with the addresses your scans leave from:'
            )}{' '}
            <Link
              href="/settings/scanning/proxies"
              className="font-medium underline-offset-2 hover:underline"
            >
              {t('sensors.scanIdent.addressesLink', 'Scanner addresses')}
            </Link>
          </p>
        </SettingsBlock>
      </SettingsSection>
      {canEdit && (
        <SettingsSaveBar
          dirty={dirty}
          saving={isUpdating}
          onSave={() => void save()}
          onDiscard={reset}
          saveDisabled={invalid}
          changes={changes}
          error={
            saveError
              ? t('settings.saveBar.failed', "Couldn't save. Your changes are kept.")
              : undefined
          }
        />
      )}
    </SettingsPage>
  )
}
