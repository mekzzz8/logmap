import React from 'react'

const RISK_COLOR  = { LOW: '#22c55e', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444' }
const SIGMA_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', informational: '#64748b' }
const SIGMA_BG    = { critical: '#450a0a', high: '#431407', medium: '#422006', low: '#052e16', informational: '#0f172a' }

const MITRE_NAMES = {
  'T1110': 'Brute Force', 'T1110.002': 'Password Cracking',
  'T1110.003': 'Password Spraying', 'T1078': 'Valid Accounts',
  'T1078.002': 'Domain Accounts', 'T1550.002': 'Pass-the-Hash',
  'T1059': 'Cmd & Scripting', 'T1059.001': 'PowerShell',
  'T1053.005': 'Scheduled Task', 'T1543.003': 'New Service',
  'T1136.001': 'Create Account', 'T1098': 'Account Manipulation',
  'T1548.003': 'Sudo Escalation', 'T1021.001': 'RDP Lateral Move',
}

const s = {
  panel: {
    background: '#080c18', padding: 14, overflowY: 'auto',
    height: '100%', display: 'flex', flexDirection: 'column', gap: 12,
  },
  sectionTitle: {
    fontSize: 9, textTransform: 'uppercase', letterSpacing: 1,
    color: '#334155', marginBottom: 6,
  },
  badge: color => ({
    display: 'inline-block',
    background: color + '18', border: `1px solid ${color}55`,
    color, borderRadius: 4, padding: '2px 8px',
    fontSize: 10, fontWeight: 600,
  }),
  card: {
    background: '#0f172a', borderRadius: 6,
    border: '1px solid #1e293b', padding: '8px 10px',
  },
}

function GaugeBar({ score, color }) {
  return (
    <div style={{ background: '#1e293b', borderRadius: 4, height: 7, overflow: 'hidden', marginTop: 6 }}>
      <div style={{
        height: '100%', width: `${Math.round((score || 0) * 100)}%`,
        background: color, borderRadius: 4, transition: 'width .4s',
      }} />
    </div>
  )
}

// ─── Technique deep-dive panel ────────────────────────────────────────────────
function TechniquePanel({ node, riskData }) {
  const tid = node.fullLabel || node.label

  // Try to find enriched data from the risk report passed from App
  const ts  = riskData?.technique_scores?.find(t => t.technique === tid)
  const riskColor = RISK_COLOR[node.risk_level] || '#64748b'

  return (
    <div style={s.panel}>
      <div style={s.sectionTitle}>Technique Detail</div>

      {/* Header */}
      <div>
        <div style={{ fontFamily: 'monospace', fontSize: 18, fontWeight: 700, color: '#a855f7' }}>{tid}</div>
        <div style={{ fontSize: 14, color: '#e2e8f0', marginTop: 2 }}>
          {ts?.name || MITRE_NAMES[tid] || 'Unknown Technique'}
        </div>
        <div style={{ marginTop: 6, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span style={s.badge(riskColor)}>{node.risk_level}</span>
          {ts?.sigma_severity && (
            <span style={{
              background: SIGMA_BG[ts.sigma_severity] || '#1e293b',
              color: SIGMA_COLOR[ts.sigma_severity] || '#64748b',
              border: `1px solid ${SIGMA_COLOR[ts.sigma_severity] || '#64748b'}55`,
              borderRadius: 4, padding: '2px 8px', fontSize: 10, fontWeight: 700,
            }}>
              σ {ts.sigma_severity.toUpperCase()}
            </span>
          )}
          {ts?.tactic_id && (
            <span style={s.badge('#38bdf8')}>{ts.tactic_id}</span>
          )}
        </div>
      </div>

      {/* Score + formula */}
      {ts && (
        <div style={s.card}>
          <div style={s.sectionTitle}>Score breakdown</div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6 }}>
            <span style={{ fontSize: 36, fontWeight: 800, color: riskColor, lineHeight: 1 }}>
              {Math.round(ts.final_score)}
            </span>
            <span style={{ color: '#334155', fontSize: 12, paddingBottom: 4 }}>/100</span>
          </div>
          <GaugeBar score={ts.final_score / 100} color={riskColor} />

          <div style={{ marginTop: 10, fontFamily: 'monospace', fontSize: 10, lineHeight: 1.8 }}>
            <div style={{ color: '#475569' }}>
              <span style={{ color: '#38bdf8' }}>tactic</span>
              {' '}({ts.tactic_score}) × 0.4
              {'  +  '}
              <span style={{ color: SIGMA_COLOR[ts.sigma_severity] || '#64748b' }}>sigma</span>
              {' '}({ts.sigma_score}) × 0.6
            </div>
            <div style={{ color: '#475569' }}>
              = {ts.base_score} &nbsp;
              <span style={{ color: '#64748b' }}>× freq_mult({ts.count} obs.)</span>
            </div>
            <div style={{ color: riskColor, fontWeight: 700 }}>
              = {Math.round(ts.final_score)} &nbsp;
              <span style={{ color: '#475569', fontWeight: 400 }}>[{ts.risk_level}]</span>
            </div>
          </div>
        </div>
      )}

      {/* MITRE tactic */}
      {ts?.tactic && (
        <div style={s.card}>
          <div style={s.sectionTitle}>MITRE Tactic</div>
          <div style={{ fontSize: 12, color: '#38bdf8' }}>{ts.tactic}</div>
          <div style={{ fontSize: 10, color: '#475569', marginTop: 2 }}>
            Tactic phase score: {ts.tactic_score}/100
          </div>
        </div>
      )}

      {/* Why this score */}
      {ts?.why && (
        <div style={s.card}>
          <div style={s.sectionTitle}>Why this score</div>
          <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.65 }}>
            {ts.why}
          </div>
        </div>
      )}

      {/* Sigma rules */}
      {ts?.sigma_rule_refs?.length > 0 && (
        <div style={s.card}>
          <div style={s.sectionTitle}>Sigma rule references</div>
          {ts.sigma_rule_refs.map(r => (
            <div key={r} style={{
              fontFamily: 'monospace', fontSize: 9, color: '#475569',
              padding: '2px 0', borderBottom: '1px solid #1e293b',
            }}>
              {r}
            </div>
          ))}
          <div style={{ fontSize: 9, color: '#334155', marginTop: 6 }}>
            Source: SigmaHQ community rules
          </div>
        </div>
      )}

      {/* Observation count */}
      <div style={{ ...s.card, display: 'flex', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 11, color: '#475569' }}>Observed in this log</span>
        <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>
          {ts?.count || node.event_count || 1}×
        </span>
      </div>
    </div>
  )
}

// ─── Generic node panel ───────────────────────────────────────────────────────
function GenericPanel({ node }) {
  const riskColor = RISK_COLOR[node.risk_level] || '#64748b'
  const techniques = node.mitre_techniques || []

  return (
    <div style={s.panel}>
      <div style={s.sectionTitle}>Node Inspector</div>

      {/* Label + badges */}
      <div>
        <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0', wordBreak: 'break-all' }}>
          {node.fullLabel || node.label}
        </div>
        <div style={{ marginTop: 6, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span style={s.badge('#38bdf8')}>{node.type}</span>
          <span style={s.badge(riskColor)}>{node.risk_level}</span>
          {node.is_suspicious && <span style={s.badge('#ef4444')}>⚠ SUSPICIOUS</span>}
        </div>
      </div>

      {/* Risk score */}
      <div style={s.card}>
        <div style={s.sectionTitle}>Risk Score</div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4 }}>
          <span style={{ fontSize: 28, fontWeight: 800, color: riskColor, lineHeight: 1 }}>
            {Math.round((node.risk_score || 0) * 100)}
          </span>
          <span style={{ color: '#334155', paddingBottom: 3 }}>/100</span>
        </div>
        <GaugeBar score={node.risk_score || 0} color={riskColor} />
      </div>

      {/* Event count */}
      <div style={{ ...s.card, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: '#475569' }}>Event count</span>
        <span style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0' }}>{node.event_count || 0}</span>
      </div>

      {/* MITRE techniques */}
      {techniques.length > 0 && (
        <div style={s.card}>
          <div style={s.sectionTitle}>Associated MITRE Techniques</div>
          {techniques.map(t => (
            <div key={t} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '5px 0', borderBottom: '1px solid #1e293b',
            }}>
              <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#a855f7', minWidth: 72 }}>{t}</span>
              <span style={{ fontSize: 11, color: '#64748b' }}>{MITRE_NAMES[t] || ''}</span>
            </div>
          ))}
        </div>
      )}

      {/* Metadata */}
      {Object.keys(node.metadata || {}).filter(k => node.metadata[k]).length > 0 && (
        <div style={s.card}>
          <div style={s.sectionTitle}>Metadata</div>
          {Object.entries(node.metadata).filter(([, v]) => v).map(([k, v]) => (
            <div key={k} style={{ fontSize: 11, color: '#64748b', marginBottom: 2 }}>
              <span style={{ color: '#334155' }}>{k}: </span>
              <span style={{ color: '#94a3b8' }}>{String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Entry point ──────────────────────────────────────────────────────────────
export default function NodeInspector({ node, riskData }) {
  if (!node) {
    return (
      <div style={{ ...s.panel, alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ fontSize: 32, marginBottom: 8 }}>🔍</div>
        <div style={{ fontSize: 12, color: '#334155', textAlign: 'center' }}>
          Click any node in the graph to inspect it
        </div>
        <div style={{ fontSize: 10, color: '#1e293b', marginTop: 4, textAlign: 'center' }}>
          MITRE technique nodes show full scoring explanation
        </div>
      </div>
    )
  }

  return node.type === 'TECHNIQUE'
    ? <TechniquePanel node={node} riskData={riskData} />
    : <GenericPanel   node={node} />
}
