import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { Area, AreaChart, Cell, Tooltip, XAxis } from './lazy-charts'

describe('lazy-charts', () => {
  it('never imports recharts at runtime outside import()', () => {
    const src = readFileSync(join(__dirname, 'lazy-charts.tsx'), 'utf8')
    const runtimeImports = src
      .split(/^(?=import\s)/m)
      .filter((stmt) => /^import\s/.test(stmt) && !/^import\s+type\b/.test(stmt))
      .filter((stmt) => /from\s+'recharts'/.test(stmt.split('\n\n')[0]))
    expect(runtimeImports).toEqual([])
  })

  it('Cell keeps the display name recharts uses to find it among Pie/Bar children', () => {
    expect(Cell.displayName).toBe('Cell')
  })

  it('renders a chart with series, axis and tooltip once recharts has loaded', async () => {
    const { container } = render(
      <div style={{ width: 400, height: 200 }}>
        <AreaChart
          width={400}
          height={200}
          data={[
            { x: 'a', y: 1 },
            { x: 'b', y: 2 },
          ]}
        >
          <XAxis dataKey="x" />
          <Tooltip />
          <Area dataKey="y" data-testid="series" />
        </AreaChart>
      </div>
    )
    await waitFor(() => expect(container.querySelector('.recharts-wrapper')).not.toBeNull())
    await waitFor(() => expect(container.querySelector('.recharts-area')).not.toBeNull())
    expect(container.querySelector('.recharts-xAxis')).not.toBeNull()
    void screen
  })
})
