import { useState, useCallback } from 'react'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || ''

export function useAnalysis() {
  const [sessionId, setSessionId]   = useState(null)
  const [stats, setStats]           = useState(null)
  const [graph, setGraph]           = useState(null)
  const [timeline, setTimeline]     = useState(null)
  const [risk, setRisk]             = useState(null)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)

  const analyze = useCallback(async (rawLogs, filename = 'upload') => {
    setLoading(true)
    setError(null)
    try {
      const ingestRes = await axios.post(`${API}/api/ingest`, {
        raw_logs: rawLogs,
        filename,
      })
      const sid = ingestRes.data.session_id
      setSessionId(sid)
      setStats(ingestRes.data)

      const [graphRes, timelineRes, riskRes] = await Promise.all([
        axios.get(`${API}/api/graph/${sid}`),
        axios.get(`${API}/api/timeline/${sid}`),
        axios.get(`${API}/api/risk/${sid}`),
      ])
      setGraph(graphRes.data)
      setTimeline(timelineRes.data)
      setRisk(riskRes.data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [])

  const reset = useCallback(() => {
    setSessionId(null)
    setStats(null)
    setGraph(null)
    setTimeline(null)
    setRisk(null)
    setError(null)
  }, [])

  return { sessionId, stats, graph, timeline, risk, loading, error, analyze, reset }
}
