import React, { useCallback, useEffect, useRef, useState } from 'react'
import CytoscapeComponent from 'react-cytoscapejs'
import cytoscape from 'cytoscape'
import coseBilkent from 'cytoscape-cose-bilkent'
import { useGraph } from '../../hooks/useGraph'

cytoscape.use(coseBilkent)

// ─── Legend data ──────────────────────────────────────────────────────────────
const LEGEND = [
  { label: 'IP Address',   color: '#ef4444', shape: '●' },
  { label: 'User Account', color: '#eab308', shape: '◆' },
  { label: 'Process',      color: '#22c55e', shape: '⬡' },
  { label: 'Host',         color: '#64748b', shape: '■' },
  { label: 'MITRE Tech.',  color: '#a855f7', shape: '■' },
  { label: 'Service/Task', color: '#06b6d4', shape: '▬' },
]

const RISK_RING = [
  { label: 'CRITICAL', color: '#ef4444' },
  { label: 'HIGH',     color: '#f97316' },
  { label: 'MEDIUM',   color: '#eab308' },
  { label: 'LOW',      color: '#22c55e' },
]

// ─── Cytoscape stylesheet ─────────────────────────────────────────────────────
const stylesheet = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      'border-color': 'data(riskColor)',
      'border-width': 'data(borderWidth)',
      'label': 'data(label)',
      'color': '#e2e8f0',
      'font-size': 10,
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 5,
      'shape': 'data(shape)',
      'width': 'data(size)',
      'height': 'data(size)',
      'transition-property': 'opacity border-width',
      'transition-duration': '150ms',
    }
  },
  {
    selector: 'node:selected',
    style: {
      'border-color': '#38bdf8',
      'border-width': 5,
      'font-size': 12,
    }
  },
  {
    selector: 'node.dimmed',
    style: { 'opacity': 0.15 }
  },
  {
    selector: 'node.highlighted',
    style: { 'opacity': 1, 'border-width': 4 }
  },
  {
    selector: 'edge',
    style: {
      'line-color': 'data(color)',
      'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'width': 'data(width)',
      'label': '',
      'font-size': 9,
      'color': '#94a3b8',
      'text-rotation': 'autorotate',
      'text-background-color': '#0a0e1a',
      'text-background-opacity': 0.9,
      'text-background-padding': '3px',
      'opacity': 0.75,
      'transition-property': 'opacity',
      'transition-duration': '150ms',
    }
  },
  {
    selector: 'edge.dimmed',
    style: { 'opacity': 0.06 }
  },
  {
    selector: 'edge.highlighted',
    style: { 'label': 'data(shortLabel)', 'opacity': 1 }
  },
  {
    selector: 'edge:selected',
    style: { 'label': 'data(label)', 'opacity': 1, 'line-color': '#38bdf8' }
  },
  {
    selector: 'edge.critical, edge.high',
    style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444' }
  },
]

const layout = {
  name: 'cose-bilkent',
  animate: true,
  animationDuration: 900,
  randomize: false,
  nodeRepulsion: 12000,
  idealEdgeLength: 140,
  edgeElasticity: 0.45,
  nestingFactor: 0.1,
  gravity: 0.2,
  numIter: 2500,
  tile: true,
  tilingPaddingVertical: 10,
  tilingPaddingHorizontal: 10,
}

// ─── Tooltip component ────────────────────────────────────────────────────────
function Tooltip({ tip }) {
  if (!tip) return null
  return (
    <div style={{
      position: 'absolute', left: tip.x + 12, top: tip.y - 8,
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: 6, padding: '6px 10px', pointerEvents: 'none',
      fontSize: 12, color: '#e2e8f0', zIndex: 10, maxWidth: 200,
      boxShadow: '0 4px 12px rgba(0,0,0,.5)',
    }}>
      <div style={{ fontWeight: 600, marginBottom: 2 }}>{tip.label}</div>
      <div style={{ color: '#94a3b8', fontSize: 11 }}>{tip.type} · {tip.risk}</div>
      {tip.events > 0 && <div style={{ color: '#64748b', fontSize: 11 }}>Events: {tip.events}</div>}
      {tip.techs?.length > 0 && (
        <div style={{ marginTop: 4, display: 'flex', gap: 3, flexWrap: 'wrap' }}>
          {tip.techs.slice(0, 3).map(t => (
            <span key={t} style={{ background: '#2d1b69', color: '#a855f7', borderRadius: 3, padding: '1px 4px', fontSize: 10 }}>{t}</span>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Legend component ─────────────────────────────────────────────────────────
function Legend({ visible, onToggle }) {
  return (
    <div style={{ position: 'absolute', bottom: 50, left: 12, zIndex: 5 }}>
      <button
        onClick={onToggle}
        style={{
          background: '#1e293b', border: '1px solid #334155', color: '#94a3b8',
          borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 11,
          marginBottom: 4, display: 'block',
        }}
      >
        {visible ? '▾ Legend' : '▸ Legend'}
      </button>
      {visible && (
        <div style={{
          background: '#0f172a', border: '1px solid #1e293b',
          borderRadius: 8, padding: '10px 12px', minWidth: 160,
        }}>
          <div style={{ fontSize: 10, color: '#475569', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
            Node Types
          </div>
          {LEGEND.map(({ label, color, shape }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
              <span style={{ color, fontSize: 14, lineHeight: 1 }}>{shape}</span>
              <span style={{ fontSize: 11, color: '#cbd5e1' }}>{label}</span>
            </div>
          ))}
          <div style={{ borderTop: '1px solid #1e293b', marginTop: 8, paddingTop: 8 }}>
            <div style={{ fontSize: 10, color: '#475569', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
              Border = Risk
            </div>
            {RISK_RING.map(({ label, color }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <div style={{ width: 20, height: 4, borderRadius: 2, background: color }} />
                <span style={{ fontSize: 11, color: '#94a3b8' }}>{label}</span>
              </div>
            ))}
          </div>
          <div style={{ borderTop: '1px solid #1e293b', marginTop: 8, paddingTop: 8, fontSize: 10, color: '#475569' }}>
            Node size ∝ risk score
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function GraphView({ graphData, onNodeSelect }) {
  const elements = useGraph(graphData)
  const cyRef    = useRef(null)
  const [tip, setTip]           = useState(null)
  const [legendOpen, setLegend] = useState(true)

  const onCyInit = useCallback(cy => {
    cyRef.current = cy

    // Node click → highlight neighbourhood + inspector
    cy.on('tap', 'node', e => {
      const node = e.target
      const neighbourhood = node.closedNeighborhood()

      cy.elements().addClass('dimmed').removeClass('highlighted')
      neighbourhood.removeClass('dimmed').addClass('highlighted')
      setTip(null)
      onNodeSelect?.(node.data())
    })

    // Background click → reset
    cy.on('tap', e => {
      if (e.target !== cy) return
      cy.elements().removeClass('dimmed highlighted')
      onNodeSelect?.(null)
      setTip(null)
    })

    // Hover tooltip
    cy.on('mouseover', 'node', e => {
      const d = e.target.data()
      const pos = e.renderedPosition
      setTip({
        x: pos.x, y: pos.y,
        label: d.fullLabel,
        type: d.type,
        risk: d.risk_level,
        events: d.event_count,
        techs: d.mitre_techniques,
      })
    })
    cy.on('mouseout', 'node', () => setTip(null))
  }, [onNodeSelect])

  useEffect(() => {
    window.__logmapExportPNG = () => {
      if (!cyRef.current) return
      const png = cyRef.current.png({ scale: 2, bg: '#0a0e1a' })
      const a = document.createElement('a')
      a.href = png; a.download = 'logmap-graph.png'; a.click()
    }
  }, [])

  if (!graphData || elements.length === 0) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100%', color: '#475569', flexDirection: 'column', gap: 12,
      }}>
        <div style={{ fontSize: 48 }}>🔍</div>
        <div style={{ fontSize: 14 }}>Upload and analyze a log file to see the attack graph</div>
      </div>
    )
  }

  return (
    <div style={{ width: '100%', height: '100%', position: 'relative' }}>
      <CytoscapeComponent
        elements={elements}
        stylesheet={stylesheet}
        layout={layout}
        cy={onCyInit}
        style={{ width: '100%', height: '100%' }}
      />

      {/* Tooltip */}
      <Tooltip tip={tip} />

      {/* Legend */}
      <Legend visible={legendOpen} onToggle={() => setLegend(v => !v)} />

      {/* Zoom controls */}
      <div style={{
        position: 'absolute', bottom: 50, right: 12,
        display: 'flex', flexDirection: 'column', gap: 4,
      }}>
        {[
          { label: '+', action: () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25), title: 'Zoom in' },
          { label: '−', action: () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8),  title: 'Zoom out' },
          { label: '⊡', action: () => cyRef.current?.fit(undefined, 40),                title: 'Fit all' },
        ].map(({ label, action, title }) => (
          <button
            key={label} onClick={action} title={title}
            style={{
              background: '#1e293b', border: '1px solid #334155', color: '#94a3b8',
              borderRadius: 6, width: 32, height: 32, cursor: 'pointer',
              fontSize: 16, lineHeight: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >{label}</button>
        ))}
      </div>

      {/* Export */}
      <button
        onClick={() => window.__logmapExportPNG?.()}
        title="Export PNG"
        style={{
          position: 'absolute', bottom: 12, right: 12,
          background: '#1e293b', border: '1px solid #334155',
          color: '#94a3b8', borderRadius: 6, padding: '5px 10px',
          cursor: 'pointer', fontSize: 11,
        }}
      >
        📷 Export PNG
      </button>

      {/* Hint bar */}
      <div style={{
        position: 'absolute', bottom: 12, left: '50%', transform: 'translateX(-50%)',
        fontSize: 10, color: '#334155', pointerEvents: 'none',
      }}>
        Click node to inspect · Click background to reset · Scroll to zoom
      </div>
    </div>
  )
}
