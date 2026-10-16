'use client'

import { useMemo, useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import type {
  CatalogAttribute,
  FieldMeta,
  MappingRow,
  MappingTransform,
  TransformKind,
} from '../types/ticket-mapping.types'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  row: MappingRow
  attr?: CatalogAttribute
  field?: FieldMeta
  transformKinds: TransformKind[]
  onSave: (t: MappingTransform) => void
}

const NONE = '__none'

/** Edits one row's transform: a value-map grid against the field's allowed
 *  values, or the user / date / number / list / join options. */
export function TransformEditor({
  open,
  onOpenChange,
  row,
  attr,
  field,
  transformKinds,
  onSave,
}: Props) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<MappingTransform>(() => ({
    ...row.transform,
    map: { ...(row.transform?.map ?? {}) },
  }))
  const kind = draft.kind ?? ''
  const allowed = field?.allowed_values ?? []

  // Rows of the value map: every enum value of the attribute, then extra keys.
  const keys = useMemo(() => {
    const ks = new Set<string>(attr?.enum ?? [])
    Object.keys(draft.map ?? {}).forEach((k) => ks.add(k))
    return Array.from(ks)
  }, [attr, draft.map])
  const [newKey, setNewKey] = useState('')

  const setMap = (k: string, v: string) => {
    const map = { ...(draft.map ?? {}) }
    if (v === '') delete map[k]
    else map[k] = v
    setDraft({ ...draft, map })
  }

  const valueInput = (value: string, onChange: (v: string) => void, id: string) =>
    allowed.length > 0 ? (
      <Select value={value || NONE} onValueChange={(v) => onChange(v === NONE ? '' : v)}>
        <SelectTrigger id={id} className="h-8">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NONE}>{t('ticketMapping.transform.unset', '(not set)')}</SelectItem>
          {allowed.map((a) => (
            <SelectItem key={a.id} value={a.name}>
              {a.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    ) : (
      <Input
        id={id}
        className="h-8"
        value={value}
        maxLength={255}
        onChange={(e) => onChange(e.target.value)}
      />
    )

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('ticketMapping.transform.title', 'Transform')}</DialogTitle>
          <DialogDescription>
            {t('ticketMapping.transform.description', '{from} → {to}', {
              from: row.source.attr ?? row.source.kind,
              to: field?.name ?? row.target.name ?? row.target.field_id,
            })}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="tm-tkind">{t('ticketMapping.transform.kind', 'Kind')}</Label>
              <Select
                value={kind || NONE}
                onValueChange={(v) =>
                  setDraft({ ...draft, kind: (v === NONE ? '' : v) as TransformKind })
                }
              >
                <SelectTrigger id="tm-tkind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {transformKinds.map((k) => (
                    <SelectItem key={k || NONE} value={k || NONE}>
                      {t(`ticketMapping.transformKind.${k || 'none'}`, k || 'none')}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {kind === 'value_map' && (
              <div className="grid gap-2">
                <Label>{t('ticketMapping.transform.valueMap', 'Value map')}</Label>
                <div className="overflow-x-auto rounded-md border">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/50 text-xs text-muted-foreground">
                      <tr>
                        <th className="p-2 text-start">
                          {t('ticketMapping.transform.openctemValue', 'OpenCTEM value')}
                        </th>
                        <th className="p-2 text-start">
                          {t('ticketMapping.transform.jiraValue', 'Jira value')}
                        </th>
                        <th className="w-10" />
                      </tr>
                    </thead>
                    <tbody>
                      {keys.map((k) => (
                        <tr key={k} className="border-t">
                          <td className="p-2 font-mono text-xs">{k}</td>
                          <td className="p-2">
                            {valueInput(draft.map?.[k] ?? '', (v) => setMap(k, v), `tm-map-${k}`)}
                          </td>
                          <td className="p-2">
                            {!(attr?.enum ?? []).includes(k) && (
                              <Button
                                variant="ghost"
                                size="icon"
                                aria-label={t('ticketMapping.common.remove', 'Remove')}
                                onClick={() => setMap(k, '')}
                              >
                                <Trash2 className="h-4 w-4" aria-hidden />
                              </Button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!(attr?.enum && attr.enum.length > 0) && (
                  <div className="flex gap-2">
                    <Input
                      value={newKey}
                      maxLength={128}
                      placeholder={t('ticketMapping.transform.newValue', 'OpenCTEM value')}
                      onChange={(e) => setNewKey(e.target.value)}
                    />
                    <Button
                      variant="outline"
                      disabled={!newKey.trim()}
                      onClick={() => {
                        setMap(newKey.trim(), allowed[0]?.name ?? newKey.trim())
                        setNewKey('')
                      }}
                    >
                      <Plus className="me-1 h-4 w-4" aria-hidden />
                      {t('ticketMapping.common.add', 'Add')}
                    </Button>
                  </div>
                )}
                <div className="grid gap-2">
                  <Label htmlFor="tm-default">
                    {t('ticketMapping.transform.default', 'Otherwise')}
                  </Label>
                  {valueInput(
                    draft.default ?? '',
                    (v) => setDraft({ ...draft, default: v }),
                    'tm-default'
                  )}
                </div>
              </div>
            )}

            {kind === 'user' && (
              <div className="grid gap-2">
                <Label htmlFor="tm-fallback">
                  {t('ticketMapping.transform.fallback', 'Fallback account id')}
                </Label>
                <Input
                  id="tm-fallback"
                  value={draft.fallback_account ?? ''}
                  maxLength={128}
                  onChange={(e) => setDraft({ ...draft, fallback_account: e.target.value.trim() })}
                />
                <p className="text-xs text-muted-foreground">
                  {t(
                    'ticketMapping.transform.fallbackHint',
                    'Used when the OpenCTEM user has no Jira account. Empty leaves the issue unassigned.'
                  )}
                </p>
              </div>
            )}

            {kind === 'number' && (
              <div className="grid gap-2">
                <Label htmlFor="tm-round">{t('ticketMapping.transform.round', 'Decimals')}</Label>
                <Input
                  id="tm-round"
                  type="number"
                  min={0}
                  max={6}
                  value={draft.round ?? 0}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      round: Math.max(0, Math.min(6, Number(e.target.value) || 0)),
                    })
                  }
                />
              </div>
            )}

            {kind === 'list' && (
              <div className="grid gap-2">
                <Label htmlFor="tm-prefix">
                  {t('ticketMapping.transform.prefix', 'Label prefix')}
                </Label>
                <Input
                  id="tm-prefix"
                  value={draft.prefix ?? ''}
                  maxLength={32}
                  placeholder="cve:"
                  onChange={(e) =>
                    setDraft({ ...draft, prefix: e.target.value.replace(/\s/g, '') })
                  }
                />
              </div>
            )}

            {kind === 'join' && (
              <div className="grid gap-2">
                <Label htmlFor="tm-sep">
                  {t('ticketMapping.transform.separator', 'Separator')}
                </Label>
                <Input
                  id="tm-sep"
                  value={draft.separator ?? ', '}
                  maxLength={8}
                  onChange={(e) => setDraft({ ...draft, separator: e.target.value })}
                />
              </div>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('ticketMapping.common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={() => {
              onSave(draft)
              onOpenChange(false)
            }}
          >
            {t('ticketMapping.common.apply', 'Apply')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
