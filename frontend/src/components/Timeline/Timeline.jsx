import React, { useMemo } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'

const SEV_COLOR = {
  LOW: '#22c55e', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444'
}

function bucketEvents(events) {
  if (!events?.length) return []
  const withTs = events.filter(e => e.timestamp)
  if (!withTs.length) return []

  const times = withTs.map(e => new Date(e.timestamp).getTime())
  const minT = Math.min(...times)
  const maxT = Math.max(...times)
  if (minT === maxT) return [{ time: new Date(minT).toISOString().slice(11, 16), total: withTs.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }]

  const BUCKETS = 20
  const step = (maxT - minT) / BUCKETS
  const buckets = Array.from({ length: BUCKETS }, (_, i) => ({
    time: new Date(minT + i * step).toISOString().slice(11, 16),
    total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
  }))

  for (const e of withTs) {
    const idx = Math.min(BUCKETS - 1, Math.floor((new Date(e.timestamp).getTime() - minT) / step))
    const sev = e.severity || 'LOW'
    buckets[idx][sev] = (buckets[idx][sev] || 0) + 1
    buckets[idx].total++
  }

  return buckets.filter(b => b.total > 0)
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, padding: '8px 12px', fontSize: 12 }}>
      <div style={{ color: '#94a3b8', marginBottom: 4 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: SEV_COLOR[p.name] || '#e2e8f0' }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  )
}

export default function Timeline({ timeline }) {
  const data = useMemo(() => bucketEvents(timeline?.events), [timeline])

  if (!data.length) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#475569', fontSize: 13 }}>
        No timeline data
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <XAxis dataKey="time" tick={{ fill: '#475569', fontSize: 10 }} />
        <YAxis tick={{ fill: '#475569', fontSize: 10 }} />
        <Tooltip content={<CustomTooltip />} />
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
          <Bar key={sev} dataKey={sev} stackId="a" fill={SEV_COLOR[sev]} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}
