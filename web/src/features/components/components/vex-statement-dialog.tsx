'use client'

/**
 * Create or edit a VEX statement about one package. The vulnerability,
 * package and asset of a statement are fixed once it exists; editing
 * changes its status, justification, statements, versions and expiry.
 */

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  createVexStatement,
  parseVersions,
  updateVexStatement,
  VEX_JUSTIFICATIONS,
  VEX_STATUSES,
  type VexApplyResult,
  type VexStatement,
  type VexStatementInput,
  type VexStatus,
} from '../api/vex'
import { AssetChooser, type ChosenAsset } from './asset-chooser'
import { useVexLabels } from './vex-labels'

type VersionMode = 'all' | 'list' | 'range'

export interface VexFormState {
  vulnId: string
  status: VexStatus
  justification: string
  impact: string
  action: string
  versionMode: VersionMode
  versions: string
  range: string
  expiresAt: string
}

export function initialVexForm(st?: VexStatement | null): VexFormState {
  return {
    vulnId: st?.vuln_id ?? '',
    status: st?.status ?? 'not_affected',
    justification: st?.justification ?? '',
    impact: st?.impact_statement ?? '',
    action: st?.action_statement ?? '',
    versionMode: st?.version_range ? 'range' : st && st.versions.length > 0 ? 'list' : 'all',
    versions: st?.versions.join(', ') ?? '',
    range: st?.version_range ?? '',
    expiresAt: st?.expires_at ? st.expires_at.slice(0, 10) : '',
  }
}

/** Client-side checks mirroring the API, as i18n keys (null = valid). */
export function validateVexForm(f: VexFormState, creating: boolean): string | null {
  if (creating && !/^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/.test(f.vulnId.trim())) {
    return 'components.vex.error.vulnId'
  }
  if (f.status === 'not_affected' && !f.justification && !f.impact.trim()) {
    return 'components.vex.error.why'
  }
  if (f.versionMode === 'list' && parseVersions(f.versions).length === 0) {
    return 'components.vex.error.versions'
  }
  if (f.versionMode === 'range' && !/^\s*(>=|<=|!=|>|<|=)/.test(f.range)) {
    return 'components.vex.error.range'
  }
  if (f.expiresAt && new Date(`${f.expiresAt}T23:59:59Z`).getTime() <= Date.now()) {
    return 'components.vex.error.expiry'
  }
  return null
}

export function vexFormPayload(
  f: VexFormState,
  productId: string,
  asset: ChosenAsset | null,
  editing: VexStatement | null
): VexStatementInput {
  const body: VexStatementInput = {
    status: f.status,
    justification: f.status === 'not_affected' ? f.justification : '',
    impact_statement: f.impact.trim(),
    action_statement: f.action.trim(),
    versions: f.versionMode === 'list' ? parseVersions(f.versions) : [],
    version_range: f.versionMode === 'range' ? f.range.trim() : '',
  }
  if (f.expiresAt) body.expires_at = new Date(`${f.expiresAt}T23:59:59Z`).toISOString()
  else if (editing?.expires_at) body.clear_expiry = true
  if (!editing) {
    body.vuln_id = f.vulnId.trim()
    body.product_id = productId
    if (asset) body.asset_id = asset.id
  }
  return body
}

export function VexStatementDialog({
  open,
  onOpenChange,
  productId,
  statement,
  onSaved,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  productId: string
  statement: VexStatement | null
  onSaved: (applied: VexApplyResult) => void
}) {
  const { t } = useTranslation()
  const labels = useVexLabels()
  const [form, setForm] = useState<VexFormState>(() => initialVexForm(statement))
  const [asset, setAsset] = useState<ChosenAsset | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const creating = !statement

  useEffect(() => {
    if (open) {
      setForm(initialVexForm(statement))
      setAsset(null)
      setError(null)
    }
  }, [open, statement])

  const set = <K extends keyof VexFormState>(key: K, value: VexFormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }))

  const invalid = useMemo(() => validateVexForm(form, creating), [form, creating])

  const save = async () => {
    if (invalid) {
      setError(t(invalid))
      return
    }
    setBusy(true)
    setError(null)
    try {
      const body = vexFormPayload(form, productId, asset, statement)
      const res = statement
        ? await updateVexStatement(statement.id, body)
        : await createVexStatement(body)
      toast.success(
        t(
          'components.vex.saved',
          'Statement saved: {closed} findings closed, {reopened} reopened.',
          {
            closed: res.applied.closed,
            reopened: res.applied.reopened,
          }
        )
      )
      onSaved(res.applied)
      onOpenChange(false)
    } catch (e) {
      setError(
        getErrorMessage(e, t('components.vex.saveFailed', 'The statement could not be saved.'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {creating
              ? t('components.vex.newTitle', 'New VEX statement')
              : t('components.vex.editTitle', 'Edit VEX statement {id}', { id: statement.vuln_id })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'components.vex.dialogHelp',
              'Not affected closes the open findings it covers as false positive; fixed resolves them. Findings from pentests, bug bounty, red team and manual entry are never closed.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {creating && (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="vex-vuln">{t('components.vex.vulnId', 'Vulnerability')}</Label>
                <Input
                  id="vex-vuln"
                  value={form.vulnId}
                  placeholder="CVE-2024-3094"
                  onChange={(e) => set('vulnId', e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('components.vex.asset', 'Asset (empty: every asset)')}</Label>
                <AssetChooser value={asset} onChange={setAsset} enabled={open} />
              </div>
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="vex-status">{t('components.vex.status', 'Status')}</Label>
              <Select value={form.status} onValueChange={(v) => set('status', v as VexStatus)}>
                <SelectTrigger id="vex-status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {VEX_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {labels.status(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {form.status === 'not_affected' && (
              <div className="space-y-2">
                <Label htmlFor="vex-just">
                  {t('components.vex.justification', 'Justification')}
                </Label>
                <Select value={form.justification} onValueChange={(v) => set('justification', v)}>
                  <SelectTrigger id="vex-just">
                    <SelectValue placeholder={t('components.vex.choose', 'Choose')} />
                  </SelectTrigger>
                  <SelectContent>
                    {VEX_JUSTIFICATIONS.map((j) => (
                      <SelectItem key={j} value={j}>
                        {labels.justification(j)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">
              {t('components.vex.versions', 'Versions')}
            </legend>
            <RadioGroup
              value={form.versionMode}
              onValueChange={(v) => set('versionMode', v as VersionMode)}
              className="flex flex-wrap gap-4"
            >
              {(['all', 'list', 'range'] as const).map((m) => (
                <div key={m} className="flex items-center gap-2">
                  <RadioGroupItem id={`vex-mode-${m}`} value={m} />
                  <Label htmlFor={`vex-mode-${m}`} className="font-normal">
                    {labels.versionMode(m)}
                  </Label>
                </div>
              ))}
            </RadioGroup>
            {form.versionMode === 'list' && (
              <Input
                aria-label={t('components.vex.versionList', 'Versions, separated by commas')}
                value={form.versions}
                placeholder="4.17.20, 4.17.21"
                onChange={(e) => set('versions', e.target.value)}
              />
            )}
            {form.versionMode === 'range' && (
              <Input
                aria-label={t('components.vex.versionRange', 'Version range')}
                value={form.range}
                placeholder=">=1.2.0,<1.4.3"
                onChange={(e) => set('range', e.target.value)}
              />
            )}
          </fieldset>

          <div className="space-y-2">
            <Label htmlFor="vex-impact">{t('components.vex.impact', 'Impact statement')}</Label>
            <Textarea
              id="vex-impact"
              rows={3}
              maxLength={2000}
              value={form.impact}
              onChange={(e) => set('impact', e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="vex-action">{t('components.vex.action', 'Action statement')}</Label>
            <Textarea
              id="vex-action"
              rows={2}
              maxLength={2000}
              value={form.action}
              onChange={(e) => set('action', e.target.value)}
            />
          </div>
          <div className="space-y-2 sm:w-1/2">
            <Label htmlFor="vex-expiry">{t('components.vex.expiry', 'Review by (optional)')}</Label>
            <Input
              id="vex-expiry"
              type="date"
              value={form.expiresAt}
              onChange={(e) => set('expiresAt', e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              {t(
                'components.vex.expiryHelp',
                'On this date the statement is withdrawn and the findings it closed reopen.'
              )}
            </p>
          </div>

          {error && (
            <p
              role="alert"
              className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={save} disabled={busy}>
            {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('components.vex.save', 'Save statement')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
