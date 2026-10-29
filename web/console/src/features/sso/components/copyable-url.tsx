'use client'

import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { copyToClipboard } from '@/lib/clipboard'
import { useTranslation } from '@/context/i18n-provider'

/** A read-only value with a copy button, for what an operator registers at an identity provider. */
export function CopyableUrl({ label, url }: { label: string; url: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-1">
      <Label className="text-muted-foreground text-xs">{label}</Label>
      <div className="flex items-center gap-2">
        <code className="bg-muted min-w-0 flex-1 truncate rounded px-2 py-1 text-xs">{url}</code>
        <Button
          type="button"
          size="icon"
          variant="ghost"
          aria-label={t('admin.copyableUrl.copy', 'Copy {label}', { label })}
          onClick={async () => {
            await copyToClipboard(url)
            setCopied(true)
            setTimeout(() => setCopied(false), 1500)
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </Button>
      </div>
    </div>
  )
}
