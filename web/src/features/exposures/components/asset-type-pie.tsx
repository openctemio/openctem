'use client'

import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from '@/components/charts'

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
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}
