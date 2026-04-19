import { useMemo } from 'react'

const TYPE_COLOR = {
  IP:        { bg: '#7f1d1d', border: '#ef4444' },
  USER:      { bg: '#713f12', border: '#eab308' },
  PROCESS:   { bg: '#14532d', border: '#22c55e' },
  HOST:      { bg: '#1e293b', border: '#64748b' },
  TECHNIQUE: { bg: '#2e1065', border: '#a855f7' },
  SERVICE:   { bg: '#164e63', border: '#06b6d4' },
  TASK:      { bg: '#431407', border: '#f97316' },
}

const TYPE_SHAPE = {
  IP:        'ellipse',
  USER:      'diamond',
  PROCESS:   'hexagon',
  HOST:      'rectangle',
  TECHNIQUE: 'rectangle',
  SERVICE:   'round-rectangle',
  TASK:      'round-rectangle',
}

const RISK_COLOR = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#475569',
}

// Node size scales with risk level so dangerous nodes stand out immediately
const RISK_SIZE = {
  CRITICAL: 54,
  HIGH:     42,
  MEDIUM:   32,
  LOW:      24,
}

const EDGE_RISK_COLOR = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#334155',
}

// Short labels for edge hover
const RELATION_SHORT = {
  AUTHENTICATED_AS: 'AUTH',
  SPAWNED:          'SPAWN',
  EXECUTED:         'EXEC',
  CONNECTED_FROM:   'CONN',
  LOGGED_INTO:      'LOGIN',
  MAPS_TO:          '→',
  CREATED:          'CREATE',
}

export function useGraph(graphData) {
  const elements = useMemo(() => {
    if (!graphData) return []

    const nodes = (graphData.nodes || []).map(n => {
      const tc = TYPE_COLOR[n.type] || { bg: '#1e293b', border: '#475569' }
      const size = RISK_SIZE[n.risk_level] || 26
      const riskColor = RISK_COLOR[n.risk_level] || '#475569'

      return {
        data: {
          id: n.id,
          label: n.label.length > 18 ? n.label.slice(0, 16) + '…' : n.label,
          fullLabel: n.label,
          type: n.type,
          risk_level: n.risk_level,
          risk_score: n.risk_score,
          event_count: n.event_count,
          is_suspicious: n.is_suspicious,
          mitre_techniques: n.mitre_techniques,
          metadata: n.metadata,
          color: tc.bg,
          riskColor,
          borderWidth: n.risk_level === 'CRITICAL' ? 4 : n.risk_level === 'HIGH' ? 3 : 2,
          shape: TYPE_SHAPE[n.type] || 'ellipse',
          size,
        },
        classes: [
          n.type.toLowerCase(),
          n.risk_level.toLowerCase(),
          n.is_suspicious ? 'suspicious' : '',
        ].filter(Boolean),
      }
    })

    const edges = (graphData.edges || []).map(e => ({
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        label: `${e.relation} ×${e.weight}`,
        shortLabel: `${RELATION_SHORT[e.relation] || e.relation} ×${e.weight}`,
        relation: e.relation,
        weight: e.weight,
        risk_level: e.risk_level,
        color: EDGE_RISK_COLOR[e.risk_level] || '#334155',
        width: Math.min(1 + Math.log2(e.weight + 1), 5),
      },
      classes: [e.risk_level.toLowerCase()],
    }))

    return [...nodes, ...edges]
  }, [graphData])

  return elements
}
