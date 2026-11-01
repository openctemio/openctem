'use client'

import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'

/** Copies value to the clipboard and says so. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        if (await copyToClipboard(value)) {
          setCopied(true)
          toast.success(t('mcp.connect.copied', '{label} copied', { label }))
          setTimeout(() => setCopied(false), 1500)
        }
      }}
    >
      {copied ? (
        <Check className="h-4 w-4" aria-hidden />
      ) : (
        <Copy className="h-4 w-4" aria-hidden />
      )}
      <span className="ml-1.5">{t('mcp.connect.copy', 'Copy')}</span>
    </Button>
  )
}

/** A labelled block of configuration or commands with a copy button. */
export function SnippetBlock({ label, code }: { label: string; code: string }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <Label>{label}</Label>
        <CopyButton value={code} label={label} />
      </div>
      <pre className="bg-muted overflow-x-auto rounded-md p-4 text-xs">
        <code>{code}</code>
      </pre>
    </div>
  )
}
