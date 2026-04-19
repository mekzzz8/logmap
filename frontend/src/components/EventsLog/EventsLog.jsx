import React, { useMemo, useState } from 'react'

const SEV_COLOR  = { LOW: '#22c55e', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444' }
const SEV_BG     = { LOW: '#052e16', MEDIUM: '#422006', HIGH: '#431407', CRITICAL: '#450a0a' }
const SEV_ORDER  = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

const SEV_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function fmt(ts) {
  if (!ts) return '—'
  try {
    const d = new Date(ts)
    return d.toLocaleTimeString('en-GB', { hour12: false }) + '\n' + d.toLocaleDateString('en-GB')
  } catch { return ts.slice(0, 16) }
}

function SevBadge({ level }) {
  const color = SEV_COLOR[level] || '#64748b'
  return (
    <span style={{
      display: 'inline-block',
      background: SEV_BG[level] || '#1e293b',
      color, border: `1px solid ${color}44`,
      borderRadius: 3, padding: '1px 5px',
      fontSize: 9, fontWeight: 700, letterSpacing: 0.5,
    }}>
      {level}
    </span>
  )
}

function EventRow({ event, index }) {
  const [expanded, setExpanded] = useState(false)
  const sev = event.severity || 'LOW'
  const barColor = SEV_COLOR[sev] || '#334155'

  return (
    <div
      onClick={() => setExpanded(v => !v)}
      style={{
        borderLeft: `3px solid ${barColor}`,
        background: expanded ? '#0f172a' : 'transparent',
        borderRadius: '0 4px 4px 0',
        marginBottom: 2, cursor: 'pointer',
        transition: 'background .1s',
      }}
    >
      {/* Collapsed row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, padding: '6px 8px' }}>
        {/* Timestamp */}
        <div style={{ minWidth: 50, fontSize: 9, color: '#475569', lineHeight: 1.4, flexShrink: 0 }}>
          {fmt(event.timestamp).split('\n').map((l, i) => <div key={i}>{l}</div>)}
        </div>

        {/* Main content */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3, flexWrap: 'wrap' }}>
            <SevBadge level={sev} />
            {event.event_id && (
              <span style={{
                background: '#1e293b', color: '#38bdf8',
                borderRadius: 3, padding: '1px 5px', fontSize: 9, fontFamily: 'monospace',
              }}>
                {event.event_id}
              </span>
            )}
            {event.is_suspicious && (
              <span style={{ color: '#ef4444', fontSize: 9 }}>⚠</span>
            )}
          </div>

          <div style={{
            fontSize: 11, color: '#cbd5e1',
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          }}>
            {event.description || '—'}
          </div>

          {/* Tags: user + ip */}
          <div style={{ display: 'flex', gap: 4, marginTop: 4, flexWrap: 'wrap' }}>
            {event.username && (
              <span style={{
                background: '#1c1400', color: '#eab308', borderRadius: 3,
                padding: '0 5px', fontSize: 9,
              }}>
                👤 {event.username}
              </span>
            )}
            {event.src_ip && (
              <span style={{
                background: '#1a0505', color: '#f87171', borderRadius: 3,
                padding: '0 5px', fontSize: 9,
              }}>
                🌐 {event.src_ip}
              </span>
            )}
            {event.mitre_techniques?.map(t => (
              <span key={t} style={{
                background: '#2d1b69', color: '#a855f7', borderRadius: 3,
                padding: '0 5px', fontSize: 9, fontFamily: 'monospace',
              }}>
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{
          padding: '0 8px 8px 66px',
          fontSize: 10, color: '#64748b', lineHeight: 1.7,
        }}>
          {event.process_name && (
            <div><span style={{ color: '#475569' }}>Process: </span>
              <span style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 9 }}>
                {event.process_name.length > 80 ? event.process_name.slice(0, 80) + '…' : event.process_name}
              </span>
            </div>
          )}
          <div><span style={{ color: '#475569' }}>Source: </span>{event.source}</div>
        </div>
      )}
    </div>
  )
}

export default function EventsLog({ timeline }) {
  const [search, setSearch]     = useState('')
  const [sevFilter, setSev]     = useState('ALL')
  const [suspOnly, setSuspOnly] = useState(false)

  const events = useMemo(() => {
    if (!timeline?.events) return []
    return [...timeline.events].sort(
      (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] ||
                (a.timestamp || '').localeCompare(b.timestamp || '')
    )
  }, [timeline])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return events.filter(e => {
      if (sevFilter !== 'ALL' && e.severity !== sevFilter) return false
      if (suspOnly && !e.is_suspicious) return false
      if (q) {
        return (
          e.description?.toLowerCase().includes(q) ||
          e.username?.toLowerCase().includes(q) ||
          e.src_ip?.includes(q) ||
          e.event_id?.includes(q) ||
          e.mitre_techniques?.some(t => t.toLowerCase().includes(q))
        )
      }
      return true
    })
  }, [events, sevFilter, suspOnly, search])

  // Counts per severity for the filter buttons
  const counts = useMemo(() => {
    const c = { ALL: events.length }
    for (const e of events) c[e.severity] = (c[e.severity] || 0) + 1
    return c
  }, [events])

  if (!timeline?.events?.length) {
    return (
      <div style={{ color: '#475569', fontSize: 13, textAlign: 'center', padding: '32px 16px' }}>
        No events to display
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Search */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e293b' }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by IP, user, ID, technique…"
          style={{
            width: '100%', background: '#0f172a', border: '1px solid #334155',
            borderRadius: 6, color: '#e2e8f0', padding: '5px 10px',
            fontSize: 11, outline: 'none',
          }}
        />
      </div>

      {/* Severity filter pills */}
      <div style={{
        display: 'flex', gap: 4, padding: '6px 12px',
        borderBottom: '1px solid #1e293b', flexWrap: 'wrap',
      }}>
        {SEV_FILTERS.map(s => {
          const active = sevFilter === s
          const color  = SEV_COLOR[s] || '#64748b'
          return (
            <button
              key={s}
              onClick={() => setSev(s)}
              style={{
                background: active ? (SEV_BG[s] || '#1e293b') : 'transparent',
                border: `1px solid ${active ? color : '#334155'}`,
                color: active ? color : '#475569',
                borderRadius: 4, padding: '2px 7px',
                fontSize: 10, cursor: 'pointer', fontWeight: active ? 700 : 400,
              }}
            >
              {s} {counts[s] !== undefined ? `(${counts[s]})` : ''}
            </button>
          )
        })}
        <button
          onClick={() => setSuspOnly(v => !v)}
          style={{
            background: suspOnly ? '#450a0a' : 'transparent',
            border: `1px solid ${suspOnly ? '#ef4444' : '#334155'}`,
            color: suspOnly ? '#ef4444' : '#475569',
            borderRadius: 4, padding: '2px 7px',
            fontSize: 10, cursor: 'pointer', marginLeft: 'auto',
          }}
        >
          ⚠ Suspicious
        </button>
      </div>

      {/* Count */}
      <div style={{ padding: '4px 12px', fontSize: 10, color: '#334155', borderBottom: '1px solid #1e293b' }}>
        Showing {filtered.length} of {events.length} events · click row to expand
      </div>

      {/* Event list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '4px 8px' }}>
        {filtered.length === 0 ? (
          <div style={{ color: '#475569', fontSize: 12, textAlign: 'center', marginTop: 24 }}>
            No events match the current filter
          </div>
        ) : (
          filtered.map((e, i) => <EventRow key={i} event={e} index={i} />)
        )}
      </div>
    </div>
  )
}
