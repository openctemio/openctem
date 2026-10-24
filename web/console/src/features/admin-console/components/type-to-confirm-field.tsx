'use client'

import { useId, useState } from 'react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { typedTextMatches } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { AdminConfirmDialog, type AdminConfirmDialogProps } from './admin-confirm-dialog'

/**
 * The typed-name step for AdminConfirmDialog (which has no such prop): render
 * it as a child and pass `canSubmit={typedTextMatches(typed, expected)}`. The
 * same matching rule as the shared ConfirmDialog (case-sensitive, trimmed).
 */
export function TypeToConfirmField({
  expected,
  value,
  onChange,
}: {
  expected: string
  value: string
  onChange: (v: string) => void
}) {
  const { t } = useTranslation()
  const id = useId()
  const [before, after = ''] = t('confirm.typeToConfirm', 'Type {text} to confirm').split('{text}')
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="block font-normal">
        {before}
        <span className="font-semibold break-all">{expected}</span>
        {after}
      </Label>
      <Input
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
    </div>
  )
}

/**
 * AdminConfirmDialog plus a typed name: the confirm button stays disabled until
 * `typeToConfirm` is typed. Mount it only while open (it keeps the typed text).
 */
export function TypedAdminConfirmDialog({
  typeToConfirm,
  children,
  canSubmit = true,
  ...props
}: AdminConfirmDialogProps & { typeToConfirm?: string }) {
  const [typed, setTyped] = useState('')
  return (
    <AdminConfirmDialog
      {...props}
      canSubmit={canSubmit && (!typeToConfirm || typedTextMatches(typed, typeToConfirm))}
    >
      {children}
      {typeToConfirm && (
        <TypeToConfirmField expected={typeToConfirm} value={typed} onChange={setTyped} />
      )}
    </AdminConfirmDialog>
  )
}

/** The text to type for an item: its name, or a short fallback when empty or over 64 characters. */
export function nameToType(name: string | undefined | null, fallback: string): string {
  const n = (name ?? '').trim()
  return n && n.length <= 64 ? n : fallback
}
