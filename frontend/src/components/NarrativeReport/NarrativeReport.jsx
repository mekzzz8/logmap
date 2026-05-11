import React, { useState } from 'react'

const SECTION_ICONS = {
  'Analysis of': '📊',
  '[Brute Force': '🔓',
  '[Password Spray': '🌊',
  '[Pass-the-Hash': '🔑',
  '[Lateral Movement': '↔️',
  '[Persistence': '⚙️',
  '[Privilege Escalation': '⬆️',
  'Top suspicious': '🎯',
  'Highest-scoring': '🛡',
  'IMMEDIATE ACTION': '🚨',
  'Prompt investigation': '⚠️',
  'Review the flagged': '📋',
  'No urgent': '✅',
}

function getSectionIcon(text) {
  for (const [key, icon] of Object.entries(SECTION_ICONS)) {
    if (text.startsWith(key)) return icon
  }
  return '•'
}

export default function NarrativeReport({ narrative }) {
  const [copied, setCopied] = useState(false)

  if (!narrative) {
    return (
      <div style={{ color: '#334155', fontSize: 12, textAlign: 'center', marginTop: 40 }}>
        No report available
      </div>
    )
  }

  const sections = narrative.split('\n\n').filter(Boolean)

  const handleCopy = () => {
    navigator.clipboard.writeText(narrative)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
        <div style={{ fontSize: 10, color: '#334155', textTransform: 'uppercase', letterSpacing: 1 }}>
          Incident Report
        </div>
        <button
          onClick={handleCopy}
          style={{
            background: 'transparent', border: '1px solid #1e293b',
            color: copied ? '#22c55e' : '#475569', borderRadius: 4,
            padding: '2px 8px', cursor: 'pointer', fontSize: 10,
            transition: 'color .2s',
          }}
        >
          {copied ? '✓ Copied' : 'Copy'}
        </button>
      </div>

      {sections.map((section, i) => {
        const isFirst = i === 0
        const isLast  = i === sections.length - 1
        const icon = getSectionIcon(section)

        const isAlert = section.startsWith('IMMEDIATE ACTION')
        const isGood  = section.startsWith('No urgent')

        const borderColor = isAlert ? '#ef4444' : isGood ? '#22c55e' : isFirst ? '#38bdf8' : '#1e293b'

        return (
          <div
            key={i}
            style={{
              background: '#0f172a',
              borderRadius: 6,
              padding: '10px 12px',
              borderLeft: `3px solid ${borderColor}`,
            }}
          >
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
              <span style={{ fontSize: 14, flexShrink: 0, marginTop: 1 }}>{icon}</span>
              <p style={{
                margin: 0,
                fontSize: 11,
                color: isAlert ? '#fca5a5' : isGood ? '#86efac' : isFirst ? '#bae6fd' : '#94a3b8',
                lineHeight: 1.7,
              }}>
                {section}
              </p>
            </div>
          </div>
        )
      })}
    </div>
  )
}
