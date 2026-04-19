import React, { useState, useRef } from 'react'

const styles = {
  wrapper: {
    display: 'flex', flexDirection: 'column', gap: 12,
    height: '100%',
  },
  dropZone: {
    border: '2px dashed #334155',
    borderRadius: 8,
    padding: '20px',
    textAlign: 'center',
    color: '#94a3b8',
    cursor: 'pointer',
    transition: 'border-color .2s, background .2s',
    fontSize: 13,
  },
  dropZoneActive: {
    borderColor: '#38bdf8',
    background: '#0f172a',
  },
  textarea: {
    flex: 1,
    background: '#0f172a',
    border: '1px solid #334155',
    borderRadius: 8,
    color: '#e2e8f0',
    padding: 12,
    fontFamily: 'monospace',
    fontSize: 12,
    resize: 'none',
    outline: 'none',
    minHeight: 180,
  },
  btn: {
    background: '#2563eb',
    color: '#fff',
    border: 'none',
    borderRadius: 6,
    padding: '10px 20px',
    cursor: 'pointer',
    fontWeight: 600,
    fontSize: 14,
    transition: 'background .2s',
  },
  btnDisabled: {
    background: '#1e3a5f',
    cursor: 'not-allowed',
  },
  error: {
    color: '#ef4444',
    fontSize: 13,
    padding: '8px 12px',
    background: '#1a0a0a',
    borderRadius: 6,
    border: '1px solid #7f1d1d',
  },
}

export default function LogInput({ onAnalyze, loading, error }) {
  const [text, setText] = useState('')
  const [dragging, setDragging] = useState(false)
  const fileRef = useRef()

  function handleFile(file) {
    const reader = new FileReader()
    reader.onload = e => setText(e.target.result)
    reader.readAsText(file)
  }

  function onDrop(e) {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }

  function submit() {
    if (text.trim() && !loading) onAnalyze(text)
  }

  return (
    <div style={styles.wrapper}>
      <div
        style={{ ...styles.dropZone, ...(dragging ? styles.dropZoneActive : {}) }}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => fileRef.current.click()}
      >
        <div style={{ fontSize: 24, marginBottom: 6 }}>📂</div>
        <div>Drop log file here or <span style={{ color: '#38bdf8' }}>click to browse</span></div>
        <div style={{ fontSize: 11, marginTop: 4 }}>Supports: Windows Event Log, auth.log, syslog</div>
        <input
          ref={fileRef}
          type="file"
          accept=".log,.txt,.evtx"
          style={{ display: 'none' }}
          onChange={e => e.target.files[0] && handleFile(e.target.files[0])}
        />
      </div>

      <textarea
        style={styles.textarea}
        placeholder="Or paste raw log content here…"
        value={text}
        onChange={e => setText(e.target.value)}
        spellCheck={false}
      />

      {error && <div style={styles.error}>⚠ {error}</div>}

      <button
        style={{ ...styles.btn, ...(loading || !text.trim() ? styles.btnDisabled : {}) }}
        onClick={submit}
        disabled={loading || !text.trim()}
      >
        {loading ? 'Analyzing…' : '⚡ Analyze Logs'}
      </button>
    </div>
  )
}
