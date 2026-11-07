'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { SettingsSaveBar } from '@/features/shared/components/settings-save-bar'
import { DetailDisclosure, ErrorState } from '@/features/shared'
import {
  HeaderListEditor,
  IdentityPreview,
  QueryParamFields,
  RequireIdentificationSwitch,
  RequiredMissingAlert,
  UserAgentRotationField,
} from '@/features/sensors/components/scan-identification-parts'
import {
  MAX_PLATFORM_HEADERS,
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
} from '@/features/sensors/lib/scan-identification'
import { saveScanIdentification, useScanIdentification } from '../api/use-platform-settings'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'

/**
 * System > Scan identification: the User-Agent (or a rotation list), headers
 * and query parameter every organization's scan jobs carry, each optionally
 * enforced (no organization, program or sensor-local layer replaces it), and
 * the main switch: require identification on every request (no organization
 * can turn it off). Organizations add their own over them. A change needs
 * the step-up and a reason.
 */
export function ScanIdentificationCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const uaId = useId()
  const uaEnfId = useId()
  const qEnfId = useId()
  const reqId = useId()
  const rotId = useId()
  const { data, error, isLoading, mutate } = useScanIdentification()
  const [ua, setUa] = useState('')
  const [uaList, setUaList] = useState('')
  const [uaEnforced, setUaEnforced] = useState(false)
  const [headers, setHeaders] = useState<IdentHeader[]>([])
  const [query, setQuery] = useState<IdentQuery>({ name: '', value: '' })
  const [queryEnforced, setQueryEnforced] = useState(false)
  const [required, setRequired] = useState(false)
  const [confirm, setConfirm] = useState(false)

  // The saved values: on load, after a save and on Discard.
  const reset = useCallback(() => {
    if (data) {
      setUa(data.user_agent)
      setUaList((data.user_agents ?? []).join('\n'))
      setUaEnforced(data.user_agent_enforced)
      setHeaders(data.headers)
      setQuery(data.query ?? { name: '', value: '' })
      setQueryEnforced(!!data.query_enforced)
      setRequired(!!data.identification_required)
    }
  }, [data])
  useEffect(reset, [reset])

  if (error) {
    return (
      <ErrorState
        title={t('admin.scanIdent.errorTitle', 'the scan identification')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !data) return <Skeleton className="h-64 w-full" />

  const userAgents = parseUserAgentList(uaList)
  const uaError = userAgentError(ua, t) ?? userAgentBothError(ua, userAgents, t)
  const qError = queryError(query, t)
  const invalid =
    !!uaError ||
    !!qError ||
    userAgentListErrors(uaList, t).length > 0 ||
    Object.keys(headerListErrors(headers, t)).length > 0
  const hasUA = ua.trim() !== '' || userAgents.length > 0
  const q = normalizeQuery(query)
  const next = {
    user_agent: ua.trim(),
    user_agents: userAgents,
    user_agent_enforced: hasUA && uaEnforced,
    headers: normalizeHeaders(headers).map((h) => ({ ...h, enforced: !!h.enforced })),
    query: q,
    query_enforced: !!q && queryEnforced,
    identification_required: required,
  }
  const dirty =
    JSON.stringify(next) !==
    JSON.stringify({
      user_agent: data.user_agent,
      user_agents: data.user_agents ?? [],
      user_agent_enforced: data.user_agent_enforced,
      headers: data.headers,
      query: data.query ?? null,
      query_enforced: !!data.query_enforced,
      identification_required: !!data.identification_required,
    })
  const identity = mergeIdentity(next, { userAgent: '', headers: [] })
  const missingMarker = requiredWithoutMarker(identity)

  const save = async (reason: string) => {
    try {
      await saveScanIdentification({ ...next, reason, version: data.version })
      void mutate()
    } catch (e) {
      if (
        handleSaveConflict(
          e,
          () => void mutate(),
          t(
            'admin.settings.conflict',
            'Another administrator changed this setting. The latest values are shown.'
          )
        )
      )
        return
      throw e
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('admin.scanIdent.title', 'Platform layer')}</CardTitle>
        <CardDescription>
          {t(
            'admin.scanIdent.description',
            "Sent with every organization's scans. An organization's own headers are added; an organization replaces a header of the same name unless it is enforced. Never put an organization's data here."
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <RequireIdentificationSwitch
          id={reqId}
          checked={required}
          onChange={setRequired}
          disabled={!canEdit}
        />
        {missingMarker && (
          <RequiredMissingAlert
            onAddHeader={
              canEdit && headers.length < MAX_PLATFORM_HEADERS
                ? () => {
                    const idx = headers.length
                    setHeaders([...headers, { name: '', value: '' }])
                    requestAnimationFrame(() =>
                      document.getElementById(`platform-scan-ident-name-${idx}`)?.focus()
                    )
                  }
                : undefined
            }
          />
        )}
        <div className="space-y-2">
          <Label htmlFor={uaId}>{t('admin.scanIdent.ua', 'User-Agent')}</Label>
          <Input
            id={uaId}
            value={ua}
            maxLength={MAX_USER_AGENT}
            placeholder={t(
              'admin.scanIdent.uaPlaceholder',
              'scanner (+https://scan.example/about)'
            )}
            aria-invalid={uaError ? true : undefined}
            onChange={(e) => setUa(e.target.value)}
            disabled={!canEdit}
          />
          {uaError && <p className="text-sm text-destructive">{uaError}</p>}
          <div className="flex items-center gap-3">
            <Switch
              id={uaEnfId}
              checked={uaEnforced}
              onCheckedChange={setUaEnforced}
              disabled={!canEdit || !hasUA}
            />
            <Label htmlFor={uaEnfId} className="font-normal">
              {t(
                'admin.scanIdent.uaEnforced',
                'Enforce: organizations cannot replace it (the User-Agent or the rotation list)'
              )}
            </Label>
          </div>
        </div>
        <div className="space-y-2">
          <Label>{t('admin.scanIdent.headers', 'Request headers')}</Label>
          <HeaderListEditor
            idPrefix="platform-scan-ident"
            headers={headers}
            onChange={setHeaders}
            max={MAX_PLATFORM_HEADERS}
            disabled={!canEdit}
            withEnforced
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
              id={rotId}
              text={uaList}
              onChange={setUaList}
              disabled={!canEdit}
            />
            <div className="space-y-2">
              <QueryParamFields
                idPrefix="platform-scan-ident"
                value={query}
                onChange={setQuery}
                disabled={!canEdit}
              />
              <div className="flex items-center gap-3">
                <Switch
                  id={qEnfId}
                  checked={queryEnforced}
                  onCheckedChange={setQueryEnforced}
                  disabled={!canEdit || !q}
                />
                <Label htmlFor={qEnfId} className="font-normal">
                  {t('admin.scanIdent.queryEnforced', 'Enforce: organizations cannot replace it')}
                </Label>
              </div>
            </div>
          </div>
        </DetailDisclosure>
        <IdentityPreview identity={identity} />
        <SettingChangedLine change={data} />
        {canEdit && (
          <SettingsSaveBar
            className="basis-full"
            dirty={dirty}
            saveDisabled={invalid}
            onSave={() => setConfirm(true)}
            onDiscard={reset}
          />
        )}
        <ReasonConfirmDialog
          open={confirm}
          onOpenChange={setConfirm}
          title={t(
            'admin.scanIdent.confirmTitle',
            'Change the scan identification of every organization?'
          )}
          desc={t(
            'admin.scanIdent.confirmDesc',
            'The new values go out with every scan job delivered from now on, for every organization.'
          )}
          confirmText={t('admin.scanIdent.confirm', 'Save scan identification')}
          onConfirm={save}
        />
      </CardContent>
    </Card>
  )
}
