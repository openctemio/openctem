'use client'

import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { ShieldCheck } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { setAdminStepUpPrompt } from '@console/lib/admin-api/client'

/**
 * The console's one step-up dialog. A protected action (an administrator,
 * the platform identity provider, an organization's owner or sign-in trust)
 * is refused with ADMIN_STEP_UP_REQUIRED until the administrator types a
 * fresh authenticator code; adminFetch then retries the same request with it.
 * One code covers the next few minutes of protected actions in this session.
 * Mounted once by the console shell.
 */
export function AdminStepUpPrompt() {
  const { t } = useTranslation()
  const codeId = useId()
  const [open, setOpen] = useState(false)
  const [code, setCode] = useState('')
  const [problem, setProblem] = useState<string | undefined>()
  const resolver = useRef<((code: string | null) => void) | null>(null)

  useEffect(() => {
    setAdminStepUpPrompt(
      (refusal) =>
        new Promise<string | null>((resolve) => {
          // A second prompt while one is open cancels the first.
          resolver.current?.(null)
          resolver.current = resolve
          setProblem(refusal)
          setCode('')
          setOpen(true)
        })
    )
    return () => {
      setAdminStepUpPrompt(null)
      resolver.current?.(null)
      resolver.current = null
    }
  }, [])

  const finish = (value: string | null) => {
    const resolve = resolver.current
    resolver.current = null
    setOpen(false)
    setCode('')
    resolve?.(value)
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (/^\d{6}$/.test(code)) finish(code)
  }

  return (
    <Dialog open={open} onOpenChange={(next) => !next && finish(null)}>
      <DialogContent>
        <DialogForm onSubmit={submit}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5" />
              {t('admin.stepUp.title', 'Confirm it is you')}
            </DialogTitle>
            <DialogDescription>
              {t(
                'admin.stepUp.description',
                'This action changes who can sign in or what they may do. Enter a fresh code from your authenticator. One code covers the next five minutes of such actions.'
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor={codeId}>
                {t('admin.confirm.code', 'Code from your authenticator')}
              </Label>
              <Input
                id={codeId}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                className="w-36 font-mono tracking-widest"
                autoFocus
                required
              />
            </div>
            {problem && (
              <Alert variant="destructive">
                <AlertDescription>{problem}</AlertDescription>
              </Alert>
            )}
          </DialogBody>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => finish(null)}>
              {t('common.cancel', 'Cancel')}
            </Button>
            <Button type="submit" disabled={!/^\d{6}$/.test(code)}>
              {t('admin.stepUp.confirm', 'Confirm')}
            </Button>
          </DialogFooter>
        </DialogForm>
      </DialogContent>
    </Dialog>
  )
}
