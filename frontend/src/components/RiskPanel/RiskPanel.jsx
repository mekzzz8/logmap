import React, { useState } from 'react'
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from 'recharts'

const RISK_COLOR  = { LOW: '#22c55e', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444' }
const SIGMA_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', informational: '#64748b' }
const SIGMA_BG    = { critical: '#450a0a', high: '#431407', medium: '#422006', low: '#052e16', informational: '#0f172a' }

function SigmaBadge({ level }) {
  const color = SIGMA_COLOR[level] || '#64748b'
  const bg    = SIGMA_BG[level]    || '#1e293b'
  return (
    <span style={{
      background: bg, color, border: `1px solid ${color}55`,
      borderRadius: 3, padding: '1px 5px',
      fontSize: 9, fontWeight: 700, letterSpacing: 0.5, textTransform: 'uppercase',
    }}>
      σ {level}
    </span>
  )
}

function TechniqueRow({ t, maxScore }) {
  const [open, setOpen] = useState(false)
  const riskColor = RISK_COLOR[t.risk_level] || '#64748b'
  const barPct    = Math.round((t.final_score / Math.max(maxScore, 1)) * 100)

  return (
    <div style={{ marginBottom: 4 }}>
      {/* Main row — click to expand */}
      <div
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 8px',
          background: open ? '#1a2234' : '#0f172a',
          borderRadius: open ? '6px 6px 0 0' : 6,
          cursor: 'pointer',
          border: `1px solid ${open ? '#334155' : 'transparent'}`,
          borderBottom: open ? 'none' : undefined,
          transition: 'background .15s',
        }}
      >
        {/* Technique ID */}
        <div style={{ minWidth: 72, fontFamily: 'monospace', fontSize: 10, color: '#a855f7', flexShrink: 0 }}>
          {t.technique}
        </div>

        {/* Name + bar */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
            <span style={{ fontSize: 10, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {t.name}
            </span>
            <SigmaBadge level={t.sigma_severity} />
          </div>
          <div style={{ background: '#1e293b', borderRadius: 3, height: 5, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 3,
              width: `${barPct}%`, background: riskColor,
              transition: 'width .4s',
            }} />
          </div>
        </div>

        {/* Score + expand toggle */}
        <div style={{ textAlign: 'right', flexShrink: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: riskColor }}>{Math.round(t.final_score)}</div>
          <div style={{ fontSize: 9, color: '#334155' }}>×{t.count} {open ? '▴' : '▾'}</div>
        </div>
      </div>

      {/* Expanded explanation panel */}
      {open && (
        <div style={{
          background: '#0a1120',
          border: '1px solid #334155', borderTop: 'none',
          borderRadius: '0 0 6px 6px',
          padding: '10px 10px 10px 12px',
        }}>
          {/* Score breakdown */}
          <div style={{
            background: '#0f172a', borderRadius: 5, padding: '7px 10px',
            marginBottom: 8, fontFamily: 'monospace', fontSize: 10,
          }}>
            <div style={{ color: '#475569', marginBottom: 4, fontSize: 9, textTransform: 'uppercase', letterSpacing: 1 }}>
              Score formula
            </div>
            <div style={{ color: '#64748b' }}>
              <span style={{ color: '#38bdf8' }}>tactic</span>
              {' '}({t.tactic_score}) × 0.4
              {' '}+ <span style={{ color: SIGMA_COLOR[t.sigma_severity] }}>sigma</span>
              {' '}({t.sigma_score}) × 0.6
            </div>
            <div style={{ color: '#475569', marginTop: 2 }}>
              = {t.base_score} × freq({t.count}) = <span style={{ color: riskColor, fontWeight: 700 }}>{Math.round(t.final_score)}</span>
            </div>
          </div>

          {/* Tactic + Sigma row */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
            <span style={{
              background: '#0f2040', color: '#38bdf8', border: '1px solid #1e3a5f',
              borderRadius: 3, padding: '2px 7px', fontSize: 9,
            }}>
              📍 {t.tactic} ({t.tactic_id})
            </span>
            <SigmaBadge level={t.sigma_severity} />
          </div>

          {/* Why explanation */}
          <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.6, marginBottom: 8 }}>
            {t.why}
          </div>

          {/* Sigma rule refs */}
          {t.sigma_rule_refs?.length > 0 && (
            <div>
              <div style={{ fontSize: 9, color: '#334155', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 }}>
                Sigma rules
              </div>
              {t.sigma_rule_refs.map(r => (
                <div key={r} style={{
                  fontFamily: 'monospace', fontSize: 9, color: '#475569',
                  padding: '1px 0',
                }}>
                  {r}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function RiskPanel({ risk, stats }) {
  const [noteOpen, setNoteOpen] = useState(false)

  if (!risk || !stats) {
    return (
      <div style={{ padding: 16, color: '#475569', fontSize: 13 }}>No data yet</div>
    )
  }

  const score     = risk.global_score || 0
  const riskColor = RISK_COLOR[risk.risk_level] || '#64748b'
  const gaugeData = [{ value: score, fill: riskColor }]
  const maxScore  = Math.max(...(risk.technique_scores || []).map(t => t.final_score), 1)

  return (
    <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>

      {/* Gauge */}
      <div style={{ position: 'relative', height: 130 }}>
        <ResponsiveContainer width="100%" height={130}>
          <RadialBarChart
            cx="50%" cy="70%" innerRadius="58%" outerRadius="100%"
            startAngle={180} endAngle={0} data={gaugeData}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar dataKey="value" cornerRadius={6} angleAxisId={0} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div style={{ position: 'absolute', bottom: 8, left: 0, right: 0, textAlign: 'center', pointerEvents: 'none' }}>
          <div style={{ fontSize: 30, fontWeight: 800, color: riskColor, lineHeight: 1 }}>{score}</div>
          <div style={{ fontSize: 11, color: riskColor, fontWeight: 600 }}>{risk.risk_level}</div>
        </div>
      </div>

      {/* Quick stats */}
      <div style={{ display: 'flex', gap: 6 }}>
        {[
          { label: 'Events',    val: stats.total_events    || 0, color: '#94a3b8' },
          { label: 'Suspicious',val: stats.suspicious_events||0, color: '#ef4444' },
          { label: 'Patterns',  val: stats.pattern_count   || 0, color: '#a855f7' },
        ].map(({ label, val, color }) => (
          <div key={label} style={{
            flex: 1, background: '#0f172a', borderRadius: 5, padding: '6px 4px', textAlign: 'center',
            border: '1px solid #1e293b',
          }}>
            <div style={{ fontSize: 16, fontWeight: 700, color }}>{val}</div>
            <div style={{ fontSize: 9, color: '#334155', textTransform: 'uppercase' }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Scoring methodology note */}
      {risk.scoring_note && (
        <div>
          <button
            onClick={() => setNoteOpen(v => !v)}
            style={{
              background: 'none', border: 'none', color: '#334155',
              fontSize: 10, cursor: 'pointer', padding: 0,
              textDecoration: 'underline',
            }}
          >
            {noteOpen ? '▴ Hide scoring methodology' : '▾ How is this score calculated?'}
          </button>
          {noteOpen && (
            <div style={{
              marginTop: 6, padding: '8px 10px',
              background: '#0f172a', borderRadius: 5,
              border: '1px solid #1e293b',
              fontSize: 10, color: '#64748b', lineHeight: 1.6,
            }}>
              {risk.scoring_note}
            </div>
          )}
        </div>
      )}

      {/* Technique list */}
      {risk.technique_scores?.length > 0 && (
        <div>
          <div style={{
            fontSize: 9, color: '#334155', textTransform: 'uppercase',
            letterSpacing: 1, marginBottom: 6,
          }}>
            Techniques — click to explain
          </div>
          {risk.technique_scores.slice(0, 10).map(t => (
            <TechniqueRow key={t.technique} t={t} maxScore={maxScore} />
          ))}
        </div>
      )}
    </div>
  )
}
