'use client'

import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from '@/components/charts'
import { LEGEND_PROPS } from './exposure-type-overview'

export interface AssetTypeSlice {
  name: string
  value: number
  color: string
}

/**
 * Asset-type ring. No labels outside the ring (they clip on a phone); the
 * legend and tooltip carry the names and counts. Loaded with next/dynamic by
 * the page so Recharts stays out of the first bundle.
 */
export default function AssetTypePie({ data }: { data: AssetTypeSlice[] }) {
  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={100}
          paddingAngle={2}
          dataKey="value"
          label={false}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip />
        {/* Names in the muted ink (series-coloured text fails contrast); the
            swatch carries the colour. */}
        <Legend {...LEGEND_PROPS} />
      </PieChart>
    </ResponsiveContainer>
  )
}
