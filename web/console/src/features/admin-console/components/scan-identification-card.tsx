'use client'

import { useEffect, useId, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useTranslation } from '@/context/i18n-provider'
import { ErrorState } from '@/features/shared'
import {
  HeaderListEditor,
  IdentityPreview,
} from '@/features/sensors/components/scan-identification-parts'
import {
  MAX_PLATFORM_HEADERS,
  MAX_USER_AGENT,
  headerListErrors,
  mergeIdentity,
  normalizeHeaders,
  userAgentError,
  type IdentHeader,
} from '@/features/sensors/lib/scan-identification'
import { saveScanIdentification, useScanIdentification } from '../api/use-platform-settings'
import {
  ReasonConfirmDialog,
  SettingChangedLine,
  handleSaveConflict,
} from './console-setting-parts'

/**
 * System > Scan identification: the User-Agent and headers every
 * organization's scan jobs carry, each optionally enforced (no organization,
 * program or sensor-local layer replaces it). Organizations add their own
 * over them. A change needs the step-up and a reason.
 */
export function ScanIdentificationCard({ canEdit }: { canEdit: boolean }) {
  const { t } = useTranslation()
  const uaId = useId()
  const uaEnfId = useId()
  const { data, error, isLoading, mutate } = useScanIdentification()
  const [ua, setUa] = useState('')
  const [uaEnforced, setUaEnforced] = useState(false)
  const [headers, setHeaders] = useState<IdentHeader[]>([])
  const [confirm, setConfirm] = useState(false)

  useEffect(() => {
    if (data) {
      setUa(data.user_agent)
      setUaEnforced(data.user_agent_enforced)
      setHeaders(data.headers)
    }
  }, [data])

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

  const uaError = userAgentError(ua, t)
  const invalid = !!uaError || Object.keys(headerListErrors(headers, t)).length > 0
  const next = {
    user_agent: ua.trim(),
    user_agent_enforced: ua.trim() !== '' && uaEnforced,
    headers: normalizeHeaders(headers).map((h) => ({ ...h, enforced: !!h.enforced })),
  }
  const dirty =
    JSON.stringify(next) !==
    JSON.stringify({
      user_agent: data.user_agent,
      user_agent_enforced: data.user_agent_enforced,
      headers: data.headers,
    })
  const identity = mergeIdentity(
    {
      user_agent: next.user_agent,
      user_agent_enforced: next.user_agent_enforced,
      headers: next.headers,
    },
    '',
    []
  )

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
              disabled={!canEdit || ua.trim() === ''}
            />
            <Label htmlFor={uaEnfId} className="font-normal">
              {t('admin.scanIdent.uaEnforced', 'Enforce: organizations cannot replace it')}
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
        <IdentityPreview identity={identity} />
        <SettingChangedLine change={data} />
        {canEdit && (
          <div className="flex justify-end">
            <Button onClick={() => setConfirm(true)} disabled={!dirty || invalid}>
              {t('admin.settings.save', 'Save')}
            </Button>
          </div>
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
