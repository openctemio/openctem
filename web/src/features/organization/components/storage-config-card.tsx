'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { AlertCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { SettingsSaveBar } from '@/features/shared'
import { useTranslation } from '@/context/i18n-provider'
import { get, patch } from '@/lib/api/client'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanMutate } from '@/lib/permissions'

const FORM_ID = 'storage-config-form'

interface StorageValues {
  provider: string
  bucket: string
  region: string
  endpoint: string
}

const LOCAL: StorageValues = { provider: 'local', bucket: '', region: '', endpoint: '' }

/**
 * Organization › General › File storage: where uploaded evidence and
 * attachments are kept (admin only, PATCH /attachments/storage-config with a
 * recent sign-in). The stored keys are never read back: the access and
 * secret key fields are write-only and empty means "keep the stored ones".
 */
export function StorageConfigCard() {
  const { t } = useTranslation()
  const canSave = useCanMutate('PATCH /api/v1/attachments/storage-config')
  const [saved, setSaved] = useState<StorageValues>(LOCAL)
  const [values, setValues] = useState<StorageValues>(LOCAL)
  const [accessKey, setAccessKey] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [loadError, setLoadError] = useState<string>()
  const [saving, setSaving] = useState(false)

  const load = useCallback(() => {
    setState('loading')
    get('/api/v1/attachments/storage-config')
      .then((data: unknown) => {
        const d = (data ?? {}) as Record<string, unknown>
        const next: StorageValues = d.configured
          ? {
              provider: (d.provider as string) || 'local',
              bucket: (d.bucket as string) || '',
              region: (d.region as string) || '',
              endpoint: (d.endpoint as string) || '',
            }
          : LOCAL
        setSaved(next)
        setValues(next)
        setState('ready')
      })
      .catch((err: unknown) => {
        // Never fall back to "local" as if that were the stored choice.
        setLoadError(getErrorMessage(err, ''))
        setState('error')
      })
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const discard = () => {
    setValues(saved)
    setAccessKey('')
    setSecretKey('')
  }

  const isCloud = values.provider === 's3' || values.provider === 'minio'
  const dirty =
    JSON.stringify(values) !== JSON.stringify(saved) || accessKey !== '' || secretKey !== ''
  const invalid =
    (isCloud && !values.bucket.trim()) || (values.provider === 'minio' && !values.endpoint.trim())

  const handleSave = async (e: FormEvent) => {
    e.preventDefault()
    if (invalid) return
    setSaving(true)
    try {
      await patch('/api/v1/attachments/storage-config', {
        ...values,
        access_key: accessKey,
        secret_key: secretKey,
      })
      toast.success(t('org.storage.saved', 'File storage saved'))
      setSaved(values)
      setAccessKey('')
      setSecretKey('')
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('org.storage.saveFailed', 'Could not save the file storage'))
      )
    } finally {
      setSaving(false)
    }
  }

  if (state === 'loading') return <Skeleton className="h-48 w-full rounded-xl" />
  if (state === 'error') {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" aria-hidden />
        <AlertTitle>
          {t('org.storage.loadFailed', 'The file storage settings could not be loaded')}
        </AlertTitle>
        <AlertDescription>
          {loadError && <p>{loadError}</p>}
          <Button variant="outline" size="sm" className="mt-2" onClick={load}>
            {t('common.retry', 'Retry')}
          </Button>
        </AlertDescription>
      </Alert>
    )
  }

  const set = (k: keyof StorageValues) => (v: string) => setValues((p) => ({ ...p, [k]: v }))
  const disabled = !canSave

  return (
    <form method="post" id={FORM_ID} onSubmit={handleSave}>
      <Card>
        <CardHeader>
          <CardTitle>{t('org.storage.title', 'Storage provider')}</CardTitle>
          <CardDescription>
            {t('org.storage.desc', 'Where uploaded evidence and attachments are stored.')}
            {disabled && ` ${t('org.storage.locked', 'Only administrators can change it.')}`}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="storage-provider">{t('org.storage.provider', 'Provider')}</Label>
            <Select value={values.provider} onValueChange={set('provider')} disabled={disabled}>
              <SelectTrigger id="storage-provider" className="w-full sm:w-[280px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="local">{t('org.storage.local', 'Local filesystem')}</SelectItem>
                <SelectItem value="s3">Amazon S3</SelectItem>
                <SelectItem value="minio">
                  {t('org.storage.minio', 'MinIO (S3-compatible)')}
                </SelectItem>
              </SelectContent>
            </Select>
            {!isCloud && (
              <p className="text-sm text-muted-foreground">
                {t(
                  'org.storage.localHelp',
                  'Files are stored on the server disk at the default storage path.'
                )}
              </p>
            )}
          </div>

          {isCloud && (
            <>
              <Separator />
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="storage-bucket">{t('org.storage.bucket', 'Bucket name')}</Label>
                  <Input
                    id="storage-bucket"
                    required
                    value={values.bucket}
                    onChange={(e) => set('bucket')(e.target.value)}
                    placeholder="my-evidence-bucket"
                    disabled={disabled}
                    aria-invalid={!values.bucket.trim()}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="storage-region">{t('org.storage.region', 'Region')}</Label>
                  <Input
                    id="storage-region"
                    value={values.region}
                    onChange={(e) => set('region')(e.target.value)}
                    placeholder="ap-southeast-1"
                    disabled={disabled}
                  />
                </div>
                {values.provider === 'minio' && (
                  <div className="space-y-2 sm:col-span-2">
                    <Label htmlFor="storage-endpoint">
                      {t('org.storage.endpoint', 'Endpoint')}
                    </Label>
                    <Input
                      id="storage-endpoint"
                      required
                      type="url"
                      value={values.endpoint}
                      onChange={(e) => set('endpoint')(e.target.value)}
                      placeholder="https://minio.internal:9000"
                      disabled={disabled}
                      aria-invalid={!values.endpoint.trim()}
                    />
                  </div>
                )}
                <div className="space-y-2">
                  <Label htmlFor="storage-access-key">
                    {t('org.storage.accessKey', 'Access key')}
                  </Label>
                  <Input
                    id="storage-access-key"
                    value={accessKey}
                    onChange={(e) => setAccessKey(e.target.value)}
                    type="password"
                    autoComplete="off"
                    disabled={disabled}
                    aria-describedby="storage-keys-help"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="storage-secret-key">
                    {t('org.storage.secretKey', 'Secret key')}
                  </Label>
                  <Input
                    id="storage-secret-key"
                    value={secretKey}
                    onChange={(e) => setSecretKey(e.target.value)}
                    type="password"
                    autoComplete="off"
                    disabled={disabled}
                    aria-describedby="storage-keys-help"
                  />
                </div>
                <p id="storage-keys-help" className="text-xs text-muted-foreground sm:col-span-2">
                  {t(
                    'org.storage.keysHelp',
                    'The stored keys are never shown. Leave both empty to keep them.'
                  )}
                </p>
              </div>
              <Alert>
                <AlertCircle className="h-4 w-4" aria-hidden />
                <AlertDescription>
                  {t(
                    'org.storage.switchNote',
                    'Files already stored stay readable after a switch: each file remembers which provider holds it.'
                  )}
                </AlertDescription>
              </Alert>
            </>
          )}
        </CardContent>
      </Card>
      <SettingsSaveBar
        dirty={dirty}
        saving={saving}
        form={FORM_ID}
        saveDisabled={invalid}
        onDiscard={discard}
      />
    </form>
  )
}
