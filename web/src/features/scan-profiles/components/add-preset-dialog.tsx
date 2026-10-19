'use client'

import * as React from 'react'
import { useState } from 'react'
import {
  Loader2,
  Radar,
  Zap,
  ShieldCheck,
  ClipboardCheck,
  Check,
  AlertTriangle,
} from 'lucide-react'
import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'

import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'

import {
  useCreateScanProfile,
  useScanProfiles,
  invalidateScanProfilesCache,
} from '@/lib/api/scan-profile-hooks'
import {
  PRESET_PROFILE_TYPES,
  PRESET_QUALITY_GATES,
  getPresetProfileRequest,
  type PresetProfileType,
} from '@/lib/api/scan-profile-types'

interface AddPresetDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const PRESET_ICONS: Record<PresetProfileType, React.ReactNode> = {
  discovery: <Radar className="h-5 w-5" />,
  quick: <Zap className="h-5 w-5" />,
  full: <ShieldCheck className="h-5 w-5" />,
  compliance: <ClipboardCheck className="h-5 w-5" />,
}

const PRESET_COLORS: Record<PresetProfileType, string> = {
  discovery: 'bg-blue-500/10 text-blue-500 border-blue-500/30',
  quick: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30',
  full: 'bg-green-500/10 text-green-500 border-green-500/30',
  compliance: 'bg-purple-500/10 text-purple-500 border-purple-500/30',
}

export function AddPresetDialog({ open, onOpenChange }: AddPresetDialogProps) {
  const { t } = useTranslation()
  const presetName = (type: PresetProfileType) => t(`scans.profiles.preset.${type}.name`)
  const [selectedPreset, setSelectedPreset] = useState<PresetProfileType | null>(null)
  const { trigger: createProfile, isMutating } = useCreateScanProfile()
  const { data: existingProfiles } = useScanProfiles({ per_page: 100 })

  // Get existing profile names for duplicate check
  const existingNames = React.useMemo(() => {
    return new Set(existingProfiles?.items?.map((p) => p.name.toLowerCase()) ?? [])
  }, [existingProfiles?.items])

  // Check if selected preset name already exists
  const isDuplicateName = selectedPreset
    ? existingNames.has(presetName(selectedPreset).toLowerCase())
    : false

  const handleCreate = async () => {
    if (!selectedPreset) return

    const name = presetName(selectedPreset)

    // Check for duplicate name before creating
    if (isDuplicateName) {
      toast.error(t('scans.profiles.preset.exists', undefined, { name }))
      return
    }

    try {
      const request = getPresetProfileRequest(
        selectedPreset,
        name,
        t(`scans.profiles.preset.${selectedPreset}.description`)
      )
      await createProfile(request)
      toast.success(t('scans.profiles.created', undefined, { name }))
      await invalidateScanProfilesCache()
      onOpenChange(false)
      setSelectedPreset(null)
    } catch (err) {
      toast.error(getErrorMessage(err, t('scans.profiles.createFailed')))
    }
  }

  const handleOpenChange = (newOpen: boolean) => {
    if (!newOpen) {
      setSelectedPreset(null)
    }
    onOpenChange(newOpen)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('scans.profiles.preset.title')}</DialogTitle>
          <DialogDescription>{t('scans.profiles.preset.desc')}</DialogDescription>
        </DialogHeader>

        <DialogBody>
          <div className="grid gap-3 py-4 md:grid-cols-2">
            {PRESET_PROFILE_TYPES.map((type) => {
              const gate = PRESET_QUALITY_GATES[type]
              const isSelected = selectedPreset === type
              const nameExists = existingNames.has(presetName(type).toLowerCase())

              return (
                <Card
                  key={type}
                  className={`cursor-pointer transition-all hover:border-primary ${
                    isSelected ? 'border-primary ring-2 ring-primary/20' : ''
                  } ${nameExists ? 'opacity-60' : ''}`}
                  onClick={() => setSelectedPreset(type)}
                >
                  <CardHeader className="pb-2">
                    <div className="flex items-start justify-between">
                      <div className={`rounded-lg p-2 ${PRESET_COLORS[type]}`}>
                        {PRESET_ICONS[type]}
                      </div>
                      {nameExists ? (
                        <div className="flex items-center gap-1 text-warning">
                          <AlertTriangle className="h-4 w-4" />
                          <span className="text-[10px]">
                            {t('scans.profiles.preset.existsBadge')}
                          </span>
                        </div>
                      ) : isSelected ? (
                        <div className="rounded-full bg-primary p-1">
                          <Check className="h-3 w-3 text-primary-foreground" />
                        </div>
                      ) : null}
                    </div>
                    <CardTitle className="text-base">{presetName(type)}</CardTitle>
                    <CardDescription className="text-xs">
                      {t(`scans.profiles.preset.${type}.description`)}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <Badge variant={gate.enabled ? 'secondary' : 'outline'} className="text-xs">
                      {gate.enabled ? t('scans.profiles.rule.on') : t('scans.profiles.rule.off')}
                    </Badge>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </DialogBody>

        <DialogFooter className="flex-col sm:flex-row">
          {isDuplicateName && (
            <p className="text-amber-500 text-xs flex items-center gap-1 me-auto">
              <AlertTriangle className="h-3 w-3" />
              {t('scans.profiles.preset.duplicate')}
            </p>
          )}
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => handleOpenChange(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!selectedPreset || isMutating || isDuplicateName}
            >
              {isMutating && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
              {t('scans.profiles.create')}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
