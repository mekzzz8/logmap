import React, { useState } from 'react'
import LogInput from './components/LogInput/LogInput'
import GraphView from './components/GraphView/GraphView'
import Timeline from './components/Timeline/Timeline'
import NodeInspector from './components/NodeInspector/NodeInspector'
import RiskPanel from './components/RiskPanel/RiskPanel'
import RecommendationCard from './components/RecommendationCard/RecommendationCard'
import EventsLog from './components/EventsLog/EventsLog'
import { useAnalysis } from './hooks/useAnalysis'

const RISK_COLOR = { LOW: '#22c55e', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444' }

const s = {
  root: {
    display: 'flex', flexDirection: 'column',
    height: '100vh', background: '#0a0e1a', color: '#e2e8f0',
    fontFamily: "'Segoe UI', system-ui, sans-serif", overflow: 'hidden',
  },
  header: {
    display: 'flex', alignItems: 'center', gap: 12,
    padding: '8px 16px', background: '#080c18',
    borderBottom: '1px solid #1e293b', flexShrink: 0,
  },
  logo: { fontSize: 18, fontWeight: 700, color: '#38bdf8', letterSpacing: 1 },
  divider: { color: '#1e293b', fontSize: 20 },
  statChip: color => ({
    background: '#0f172a', border: '1px solid #1e293b',
    borderRadius: 6, padding: '3px 10px',
    fontSize: 11, color: color || '#94a3b8',
    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1,
  }),
  statVal: { fontWeight: 700, fontSize: 14, color: 'inherit' },
  body: { display: 'flex', flex: 1, overflow: 'hidden' },
  // Left panel holds upload OR post-analysis tabs
  leftPanel: {
    width: 300, flexShrink: 0, borderRight: '1px solid #1e293b',
    display: 'flex', flexDirection: 'column', background: '#080c18',
    overflow: 'hidden',
  },
  center: { flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' },
  graphArea: { flex: 1, position: 'relative', overflow: 'hidden' },
  timelineBar: {
    height: 110, flexShrink: 0,
    borderTop: '1px solid #1e293b',
    padding: '4px 8px 0',
    background: '#080c18',
  },
  timelineLabel: {
    fontSize: 9, color: '#334155', textTransform: 'uppercase',
    letterSpacing: 1, paddingLeft: 4, paddingBottom: 2,
  },
  rightPanel: {
    width: 270, flexShrink: 0, borderLeft: '1px solid #1e293b',
    display: 'flex', flexDirection: 'column', background: '#080c18',
    overflow: 'hidden',
  },
  tabs: {
    display: 'flex', gap: 2, padding: '6px 10px',
    borderBottom: '1px solid #1e293b', flexShrink: 0,
  },
  tab: active => ({
    padding: '4px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 11,
    background: active ? '#1e3a5f' : 'transparent',
    color: active ? '#93c5fd' : '#475569',
    border: 'none', transition: 'all .15s', fontWeight: active ? 600 : 400,
  }),
}

function TabBar({ tabs, active, onChange }) {
  return (
    <div style={s.tabs}>
      {tabs.map(({ id, label }) => (
        <button key={id} style={s.tab(active === id)} onClick={() => onChange(id)}>
          {label}
        </button>
      ))}
    </div>
  )
}

export default function App() {
  const { stats, graph, timeline, risk, loading, error, analyze, reset } = useAnalysis()
  const [selectedNode, setSelectedNode] = useState(null)
  const [leftTab,  setLeftTab]  = useState('summary')
  const [rightTab, setRightTab] = useState('inspector')

  const riskColor = stats ? RISK_COLOR[stats.risk_level] || '#64748b' : '#64748b'

  return (
    <div style={s.root}>

      {/* ── Header ─────────────────────────────────────────────── */}
      <div style={s.header}>
        <div style={s.logo}>⚡ LogMap</div>
        <div style={s.divider}>|</div>
        <div style={{ fontSize: 11, color: '#334155' }}>Blue Team Log Analyzer</div>
        <div style={{ flex: 1 }} />

        {stats && <>
          {[
            { label: 'Nodes',      val: stats.node_count,         color: '#38bdf8'  },
            { label: 'Edges',      val: stats.edge_count,         color: '#64748b'  },
            { label: 'Events',     val: stats.total_events,       color: '#94a3b8'  },
            { label: 'Suspicious', val: stats.suspicious_events,  color: '#ef4444'  },
            { label: 'Risk',       val: `${stats.risk_score}/100 ${stats.risk_level}`, color: riskColor },
          ].map(({ label, val, color }) => (
            <div key={label} style={s.statChip(color)}>
              <span style={s.statVal}>{val}</span>
              <span style={{ fontSize: 9, color: '#334155' }}>{label}</span>
            </div>
          ))}
          <button
            onClick={() => { reset(); setLeftTab('summary'); setRightTab('inspector') }}
            style={{
              background: 'transparent', border: '1px solid #1e293b',
              color: '#475569', borderRadius: 5, padding: '3px 10px',
              cursor: 'pointer', fontSize: 11,
            }}
          >✕ Reset</button>
        </>}
      </div>

      <div style={s.body}>

        {/* ── Left Panel ─────────────────────────────────────────── */}
        <div style={s.leftPanel}>
          {!stats ? (
            // Upload screen
            <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
              <div style={{ fontSize: 10, color: '#334155', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>
                Upload Logs
              </div>
              <LogInput onAnalyze={analyze} loading={loading} error={error} />
            </div>
          ) : (
            // Post-analysis: Summary | Events | Recs
            <>
              <TabBar
                tabs={[
                  { id: 'summary', label: '📊 Summary' },
                  { id: 'events',  label: `📋 Events (${stats.total_events})` },
                  { id: 'recs',    label: '🛡 Actions' },
                ]}
                active={leftTab}
                onChange={setLeftTab}
              />

              <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>

                {leftTab === 'summary' && (
                  <div style={{ flex: 1, overflowY: 'auto' }}>
                    {/* Quick stats */}
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e293b' }}>
                      <div style={{ fontSize: 10, color: '#334155', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                        Analysis Summary
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                        {[
                          { label: 'Format',   val: stats.format?.toUpperCase() },
                          { label: 'Patterns', val: stats.pattern_count, color: '#a855f7' },
                          { label: 'Nodes',    val: stats.node_count,    color: '#38bdf8' },
                          { label: 'Edges',    val: stats.edge_count,    color: '#64748b' },
                        ].map(({ label, val, color }) => (
                          <div key={label} style={{
                            background: '#0f172a', borderRadius: 6, padding: '7px 10px',
                          }}>
                            <div style={{ fontSize: 16, fontWeight: 700, color: color || '#e2e8f0' }}>{val}</div>
                            <div style={{ fontSize: 9, color: '#334155', textTransform: 'uppercase' }}>{label}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                    {/* Risk gauge */}
                    <RiskPanel risk={risk} stats={stats} />
                  </div>
                )}

                {leftTab === 'events' && (
                  <EventsLog timeline={timeline} />
                )}

                {leftTab === 'recs' && (
                  <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
                    <div style={{ fontSize: 10, color: '#334155', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                      Recommended Actions
                    </div>
                    <RecommendationCard risk={risk} />
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* ── Center: graph + timeline ────────────────────────────── */}
        <div style={s.center}>
          <div style={s.graphArea}>
            <GraphView graphData={graph} onNodeSelect={node => {
              setSelectedNode(node)
              if (node) setRightTab('inspector')
            }} />
          </div>
          <div style={s.timelineBar}>
            <div style={s.timelineLabel}>Event timeline</div>
            <Timeline timeline={timeline} />
          </div>
        </div>

        {/* ── Right Panel ─────────────────────────────────────────── */}
        <div style={s.rightPanel}>
          <TabBar
            tabs={[
              { id: 'inspector', label: '🔍 Inspector' },
              { id: 'patterns',  label: `⚠ Patterns${risk?.patterns?.length ? ` (${risk.patterns.length})` : ''}` },
            ]}
            active={rightTab}
            onChange={setRightTab}
          />

          <div style={{ flex: 1, overflowY: 'auto' }}>
            {rightTab === 'inspector' && (
              <NodeInspector node={selectedNode} riskData={risk} />
            )}

            {rightTab === 'patterns' && (
              <div style={{ padding: 12 }}>
                {risk?.patterns?.length > 0 ? risk.patterns.map((p, i) => {
                  const pColor = p.severity === 'CRITICAL' ? '#ef4444' : p.severity === 'HIGH' ? '#f97316' : '#eab308'
                  return (
                    <div key={i} style={{
                      background: '#0f172a', borderRadius: 6, padding: 10,
                      marginBottom: 8, borderLeft: `3px solid ${pColor}`,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <span style={{
                          background: pColor + '22', color: pColor,
                          borderRadius: 3, padding: '1px 6px', fontSize: 9, fontWeight: 700,
                        }}>
                          {p.pattern_type.replace('_', ' ')}
                        </span>
                        <span style={{ fontSize: 9, color: '#334155' }}>{p.severity}</span>
                      </div>
                      <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>{p.description}</div>
                      {p.entities?.length > 0 && (
                        <div style={{ marginTop: 6, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                          {p.entities.slice(0, 4).map(e => (
                            <span key={e} style={{
                              background: '#1e293b', color: '#64748b',
                              borderRadius: 3, padding: '1px 5px', fontSize: 9,
                            }}>{e}</span>
                          ))}
                        </div>
                      )}
                      {p.mitre_techniques?.length > 0 && (
                        <div style={{ marginTop: 5, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                          {p.mitre_techniques.map(t => (
                            <span key={t} style={{
                              background: '#2d1b69', color: '#a855f7',
                              borderRadius: 3, padding: '1px 5px', fontSize: 9, fontFamily: 'monospace',
                            }}>{t}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                }) : (
                  <div style={{ color: '#334155', fontSize: 12, textAlign: 'center', marginTop: 40 }}>
                    No attack patterns detected
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  )
}
