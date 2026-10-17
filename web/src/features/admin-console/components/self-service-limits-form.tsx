'use client'

import { useEffect, useId, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import { useLimitKeyLabel } from '@/features/limits/components/limits-usage-table'
import { LIMIT_KEYS, parseLimit, UNLIMITED, type LimitKey } from '@/features/limits/lib/limit-keys'
import type { SelfServiceLimitsResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import { saveSelfServiceLimits } from '../api/use-limits'

type Values = Record<LimitKey, string>

function toValues(d: SelfServiceLimitsResponse): Values {
  const out = {} as Values
  for (const k of LIMIT_KEYS) {
    const v = d.limits?.[k]
    out[k] = v === undefined || v === UNLIMITED ? '' : String(v)
  }
  return out
}

export interface SelfServiceLimitsFormProps {
  defaults: SelfServiceLimitsResponse
  /** False for an administrator who may read but not change them. */
  canEdit: boolean
  onSaved: () => void
}

/**
 * System > Limits: the limits an organization starts with when a person
 * creates it themselves, and the per-person organization cap. Empty means
 * unlimited, the default. Existing organizations keep theirs. A change needs
 * a fresh authenticator code.
 */
export function SelfServiceLimitsForm({ defaults, canEdit, onSaved }: SelfServiceLimitsFormProps) {
  const { t } = useTranslation()
  const keyLabel = useLimitKeyLabel()
  const initial = useMemo(() => toValues(defaults), [defaults])
  const [values, setValues] = useState<Values>(initial)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const codeId = useId()

  useEffect(() => setValues(initial), [initial])

  const invalid = LIMIT_KEYS.some((k) => parseLimit(values[k]) === null)
  const dirty = LIMIT_KEYS.some((k) => values[k] !== initial[k])
  const sources = (defaults.sources ?? []).filter((s) => s !== 'none')

  const save = async () => {
    setBusy(true)
    setCodeError(null)
    const limits: Record<string, number> = {}
    for (const k of LIMIT_KEYS) {
      const v = parseLimit(values[k])
      if (v !== null && v !== UNLIMITED) limits[k] = v
    }
    try {
      await saveSelfServiceLimits({
        limits,
        version: defaults.version ?? 0,
        totp_code: code.trim(),
      })
      setConfirmOpen(false)
      toast.success(t('limits.console.defaults.saved', 'Default limits saved'))
      onSaved()
    } catch (e) {
      if (e instanceof AdminApiError && e.status === 401) {
        setCodeError(e.message)
        setCode('')
        return
      }
      setConfirmOpen(false)
      if (e instanceof AdminApiError && e.status === 409) {
        toast.error(
          t(
            'limits.console.defaults.conflict',
            'Another administrator changed the default limits. The latest values are shown.'
          )
        )
        onSaved()
        return
      }
      toast.error(
        e instanceof Error
          ? e.message
          : t('limits.console.defaults.saveError', 'Could not save the default limits')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>
            {t('limits.console.defaults.title', 'Limits of self-service organizations')}
          </CardTitle>
          <CardDescription>
            {t(
              'limits.console.defaults.description',
              'The limits an organization starts with when a person creates it themselves. Leave a value empty for no limit (the default). Organizations created in this console have no limits, and existing organizations keep theirs.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {sources.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-sm" data-testid="limit-sources">
              <span className="text-muted-foreground">
                {t('limits.console.sources', 'Also set by:')}
              </span>
              {sources.map((s) => (
                <Badge key={s} variant="secondary">
                  {s === 'control_plane'
                    ? t('limits.console.origin.control_plane', 'The service operator')
                    : s}
                </Badge>
              ))}
            </div>
          )}
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('limits.col.item', 'Limit')}</TableHead>
                  <TableHead>{t('limits.console.defaults.start', 'Starts with')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {LIMIT_KEYS.map((k) => (
                  <TableRow key={k}>
                    <TableCell className="font-medium">{keyLabel(k)}</TableCell>
                    <TableCell>
                      <Input
                        value={values[k]}
                        onChange={(e) => setValues((v) => ({ ...v, [k]: e.target.value }))}
                        placeholder={t('limits.unlimited', 'Unlimited')}
                        inputMode="numeric"
                        className="h-8 w-28"
                        disabled={!canEdit}
                        aria-label={keyLabel(k)}
                        aria-invalid={parseLimit(values[k]) === null}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {invalid && (
            <p className="text-sm text-destructive">
              {t(
                'limits.console.invalidValue',
                'Use a whole number of 0 or more, or leave it empty for no limit.'
              )}
            </p>
          )}
          <div className="flex justify-end">
            {canEdit ? (
              <Button
                onClick={() => {
                  setCode('')
                  setCodeError(null)
                  setConfirmOpen(true)
                }}
                disabled={!dirty || invalid || busy}
              >
                {t('limits.console.save', 'Save')}
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground">
                {t('limits.console.defaults.superOnly', 'Only a super admin can change them.')}
              </p>
            )}
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!busy) setConfirmOpen(open)
        }}
        title={t('limits.console.defaults.confirmTitle', 'Change the default limits?')}
        desc={
          <p>
            {t(
              'limits.console.defaults.confirmDesc',
              'Applies to organizations people create from now on. Nothing changes for existing organizations. The change is recorded in the admin audit log.'
            )}
          </p>
        }
        disabled={code.trim().length < 6}
        isLoading={busy}
        handleConfirm={() => void save()}
        confirmText={
          busy ? (
            <>
              <Loader2 className="me-1.5 size-4 animate-spin" />
              {t('limits.console.saving', 'Saving')}
            </>
          ) : (
            t('limits.console.confirm', 'Confirm')
          )
        }
      >
        <div className="space-y-2">
          <Label htmlFor={codeId}>{t('limits.console.code', 'Code from your authenticator')}</Label>
          <Input
            id={codeId}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={8}
            aria-invalid={!!codeError}
          />
          {codeError && <p className="text-sm text-destructive">{codeError}</p>}
        </div>
      </ConfirmDialog>
    </>
  )
}
