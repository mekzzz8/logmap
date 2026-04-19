import React from 'react'

const RECS = {
  'T1110':     ['Enable account lockout policy', 'Block offending IPs at firewall'],
  'T1110.003': ['Require MFA on all accounts', 'Alert on >3 failures/user in 1h'],
  'T1078':     ['Reset compromised account credentials', 'Review privileged account activity'],
  'T1550.002': ['Enable Protected Users security group', 'Audit NTLM usage'],
  'T1059.001': ['Restrict PowerShell execution policy', 'Enable Script Block Logging'],
  'T1053.005': ['Audit scheduled tasks', 'Alert on new task creation'],
  'T1543.003': ['Audit new services', 'Restrict service installation permissions'],
  'T1548.003': ['Audit sudoers file', 'Enable sudo logging'],
  'T1021.001': ['Restrict RDP access', 'Enable NLA for RDP'],
  'BRUTE_FORCE':    ['Block IPs exceeding failed-login threshold'],
  'SPRAY_ATTACK':   ['Enable smart lockout', 'Deploy Credential Guard'],
  'PASS_THE_HASH':  ['Disable NTLM', 'Enable Protected Users group'],
  'LATERAL_MOVE':   ['Segment network, restrict RDP between hosts'],
  'PERSISTENCE':    ['Audit task/service creation', 'Enable application whitelisting'],
  'PRIV_ESCALATION':['Review privileged account activity', 'Implement just-in-time access'],
}

const PRIO = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

export default function RecommendationCard({ risk }) {
  if (!risk) return null

  const seen = new Set()
  const recs = []

  const techniques = [...(risk.technique_scores || [])].sort(
    (a, b) => (PRIO[a.risk_level] ?? 4) - (PRIO[b.risk_level] ?? 4)
  )

  for (const ts of techniques) {
    for (const r of RECS[ts.technique] || []) {
      if (!seen.has(r)) { seen.add(r); recs.push({ text: r, level: ts.risk_level, source: ts.technique }) }
    }
  }

  for (const ptype of Object.keys(risk.pattern_contributions || {})) {
    for (const r of RECS[ptype] || []) {
      if (!seen.has(r)) { seen.add(r); recs.push({ text: r, level: 'HIGH', source: ptype }) }
    }
  }

  if (!recs.length) return null

  const COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {recs.slice(0, 8).map((r, i) => (
        <div key={i} style={{
          display: 'flex', alignItems: 'flex-start', gap: 10,
          background: '#0f172a', borderRadius: 6, padding: '8px 12px',
          borderLeft: `3px solid ${COLOR[r.level] || '#64748b'}`,
        }}>
          <span style={{ color: '#38bdf8', fontWeight: 700, minWidth: 20, fontSize: 12 }}>[{i + 1}]</span>
          <div>
            <div style={{ fontSize: 13, color: '#e2e8f0' }}>{r.text}</div>
            <div style={{ fontSize: 10, color: '#475569', marginTop: 2 }}>{r.source}</div>
          </div>
        </div>
      ))}
    </div>
  )
}
