'use client'

import { Server, Database, Radar, LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { SensorType } from '@/lib/api/sensor-types'

interface SensorTypeIconProps {
  type: SensorType
  className?: string
}

// Sensor types: worker (daemon), collector (assets), sensor (EASM)
const SENSOR_TYPE_ICONS: Record<SensorType, LucideIcon> = {
  worker: Server, // Long-running daemon
  collector: Database, // Asset discovery
  sensor: Radar, // EASM monitoring
}

export function SensorTypeIcon({ type, className }: SensorTypeIconProps) {
  const Icon = SENSOR_TYPE_ICONS[type] || Server
  return <Icon className={cn('h-4 w-4', className)} />
}
