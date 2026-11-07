'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import Link from '@/components/link'
import { toast } from 'sonner'
import { Main } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  DetailDisclosure,
  PageHeader,
  PageStack,
  ReadOnlyNotice,
  SettingsSaveBar,
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
  SettingsLoadError,
  SettingsLoading,
} from '@/features/organization/components/settings-load-state'
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
  RequireIdentificationSwitch,
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
  const reset = useCallback(() => setForm(saved), [saved])
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

  const save = async () => {
    if (invalid) return
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
      toast.error(
        getErrorMessage(
          err,
          t('sensors.scanIdent.saveFailed', 'Could not save the scan identification')
        )
      )
    }
  }

  const header = (
    <PageHeader
      title={t('settings.item.scan-identification', 'Scan identification')}
      description={t(
        'sensors.scanIdent.desc',
        'Mark your scan traffic so the WAF, SIEM and logs of the scanned systems can tell it apart from other traffic.'
      )}
    />
  )
  if (isLoading) return <SettingsLoading header={header} />
  if (isError)
    return <SettingsLoadError header={header} error={error} onRetry={() => void mutate()} />
  const disabled = !canEdit
  const platformHeaders = platform?.headers ?? []

  return (
    <Main>
      <PageStack>
        {header}
        <LastChanged resourceType="tenant" resourceId={tenantId} fields={SCAN_IDENT_FIELDS} />
        {disabled && (
          <ReadOnlyNotice
            reason={t(
              'org.auth.ownerOnly',
              'Only the organization owner can change these settings.'
            )}
          />
        )}
        <Card>
          <CardContent className="space-y-4 pt-6">
            <RequireIdentificationSwitch
              id="scan-ident-required"
              checked={form.required}
              onChange={(required) => setForm((f) => ({ ...f, required }))}
              disabled={disabled}
              lockedBy={
                platform?.identification_required
                  ? t('sensors.scanIdent.required.byPlatform', 'the platform')
                  : undefined
              }
            />
            {missingMarker && (
              <RequiredMissingAlert onAddHeader={disabled ? undefined : addHeader} />
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{t('sensors.scanIdent.markers', 'What your scans send')}</CardTitle>
            <CardDescription>
              {t(
                'sensors.scanIdent.markersDesc',
                'Sent on every HTTP request of every scan, retest and validation. Saved together with Save changes.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div id="user-agent" className="space-y-2">
              <Label htmlFor="scan-ident-ua">
                {t('sensors.httpPolicy.ua.label', 'User-Agent of scan tools')}
              </Label>
              <p className="text-sm text-muted-foreground" id="scan-ident-ua-desc">
                {t('sensors.httpPolicy.ua.help')}
              </p>
              <Input
                id="scan-ident-ua"
                aria-describedby="scan-ident-ua-desc"
                aria-invalid={uaError ? true : undefined}
                placeholder="acme-security-scan (+soc@acme.example)"
                value={form.userAgent}
                maxLength={MAX_USER_AGENT}
                onChange={(e) => setForm((f) => ({ ...f, userAgent: e.target.value }))}
                disabled={disabled || uaLocked}
              />
              {uaError && <p className="text-sm text-destructive">{uaError}</p>}
              {platform?.user_agent && (
                <p className="text-sm text-muted-foreground">
                  {platform.user_agent_enforced
                    ? t('sensors.scanIdent.uaEnforced', 'The platform sets the User-Agent:')
                    : t(
                        'sensors.scanIdent.uaDefault',
                        'Platform default, used while this is empty:'
                      )}{' '}
                  <span className="font-mono">{platform.user_agent}</span>
                </p>
              )}
              {(platform?.user_agents?.length ?? 0) > 0 && (
                <p className="text-sm text-muted-foreground">
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
            </div>
            <div id="headers" className="space-y-2">
              <Label htmlFor="scan-ident-name-0">
                {t('sensors.scanIdent.headers', 'Request headers')}
              </Label>
              <p className="text-sm text-muted-foreground">
                {t(
                  'sensors.scanIdent.headersHelp',
                  'Any name and value, for example ATTT: is-here. Names are not case-sensitive. Connection, proxy, Host, Authorization and Cookie headers cannot be set.'
                )}
              </p>
              <HeaderListEditor
                idPrefix="scan-ident"
                headers={form.headers}
                onChange={(headers) => setForm((f) => ({ ...f, headers }))}
                max={MAX_ORGANIZATION_HEADERS}
                disabled={disabled}
              />
            </div>
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
                  <p className="text-sm text-muted-foreground">
                    {sourceLabel(platform.query_enforced ? 'platform_enforced' : 'platform')}:{' '}
                    <span className="font-mono">
                      ?{platform.query.name}={platform.query.value}
                    </span>
                  </p>
                )}
              </div>
            </DetailDisclosure>
            {platformHeaders.length > 0 && (
              <div className="space-y-2">
                <p className="text-sm font-medium">
                  {t('sensors.scanIdent.platformHeaders', 'Set by the platform')}
                </p>
                <ul className="space-y-1 text-sm">
                  {platformHeaders.map((h) => (
                    <li key={h.name} className="flex flex-wrap items-center gap-2">
                      <span className="font-mono">
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
                  <p className="text-sm text-destructive">
                    {t(
                      'sensors.scanIdent.overridden',
                      'The platform enforces {names}; your value for it is not sent.',
                      { names: identity.overridden.join(', ') }
                    )}
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>
        <Card id="preview">
          <CardHeader>
            <CardTitle>{t('sensors.scanIdent.preview', 'What a target receives')}</CardTitle>
          </CardHeader>
          <CardContent>
            <IdentityPreview identity={identity} />
          </CardContent>
        </Card>
        <p className="text-sm text-muted-foreground">
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
        <SettingsSaveBar
          dirty={dirty}
          saving={isUpdating}
          onSave={() => void save()}
          onDiscard={reset}
          saveDisabled={invalid}
        />
      </PageStack>
    </Main>
  )
}
