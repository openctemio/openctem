'use client'

import { useEffect, useState } from 'react'
import { Download, Loader2 } from 'lucide-react'
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
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import { downloadSbom } from '../api/download-sbom'
import type { SbomFormat } from '../api/types'
import { AssetChooser, type ChosenAsset } from './asset-chooser'

type Scope = 'all' | 'asset'

/** Download an SBOM of one asset or of every asset the caller may see. */
export function SbomExportDialog({
  open,
  onOpenChange,
  initialAsset = null,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  initialAsset?: ChosenAsset | null
}) {
  const { t } = useTranslation()
  const [format, setFormat] = useState<SbomFormat>('cyclonedx')
  const [scope, setScope] = useState<Scope>(initialAsset ? 'asset' : 'all')
  const [asset, setAsset] = useState<ChosenAsset | null>(initialAsset)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (open) {
      setScope(initialAsset ? 'asset' : 'all')
      setAsset(initialAsset)
    }
  }, [open, initialAsset])

  const download = async () => {
    setBusy(true)
    try {
      const name = await downloadSbom(format, scope === 'asset' ? asset?.id : undefined)
      toast.success(t('components.export.done', 'Downloaded {name}', { name }))
      onOpenChange(false)
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : t('components.export.failed', 'The export failed')
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('components.export.title', 'Export an SBOM')}</DialogTitle>
          <DialogDescription>
            {t(
              'components.export.description',
              'The document lists the packages, versions and licenses, with open vulnerability counts.'
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">
              {t('components.export.format', 'Format')}
            </legend>
            <RadioGroup value={format} onValueChange={(v) => setFormat(v as SbomFormat)}>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="cyclonedx" id="sbom-cdx" />
                <Label htmlFor="sbom-cdx" className="font-normal">
                  CycloneDX 1.6 (JSON)
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="spdx" id="sbom-spdx" />
                <Label htmlFor="sbom-spdx" className="font-normal">
                  SPDX 2.3 (JSON)
                </Label>
              </div>
            </RadioGroup>
          </fieldset>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">
              {t('components.export.scope', 'Contents')}
            </legend>
            <RadioGroup value={scope} onValueChange={(v) => setScope(v as Scope)}>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="all" id="sbom-all" />
                <Label htmlFor="sbom-all" className="font-normal">
                  {t('components.export.all', 'Every asset I can see')}
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem value="asset" id="sbom-asset" />
                <Label htmlFor="sbom-asset" className="font-normal">
                  {t('components.export.one', 'One asset')}
                </Label>
              </div>
            </RadioGroup>
            {scope === 'asset' && <AssetChooser value={asset} onChange={setAsset} enabled={open} />}
          </fieldset>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button onClick={download} disabled={busy || (scope === 'asset' && !asset)}>
            {busy ? (
              <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />
            ) : (
              <Download className="me-2 h-4 w-4" aria-hidden />
            )}
            {t('components.export.download', 'Download')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
