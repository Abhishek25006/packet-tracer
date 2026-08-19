import { useEffect, useState } from 'react'

export default function HistoryPanel({ refreshKey, onSelectSession }) {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)

  const loadSessions = async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/sessions')
      if (res.ok) {
        setSessions(await res.json())
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadSessions()
  }, [refreshKey])

  const handleDelete = async (id, e) => {
    e.stopPropagation()
    await fetch(`/api/sessions/${id}`, { method: 'DELETE' })
    loadSessions()
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="eyebrow">Saved</span>
        <h2>Session history</h2>
      </div>

      {loading && <div className="feed-empty">Loading...</div>}
      {!loading && sessions.length === 0 && (
        <div className="feed-empty">No saved sessions yet — stop a capture or analyze a .pcap to save one.</div>
      )}

      <div className="history-list">
        {sessions.map((s) => (
          <div
            className="history-row"
            key={s.id}
            onClick={() => onSelectSession(s.id)}
          >
            <div className="history-main">
              <span className={`history-source ${s.source === 'live' ? 'src-live' : 'src-pcap'}`}>
                {s.source === 'live' ? 'LIVE' : 'PCAP'}
              </span>
              <span className="history-label">{s.label || 'unnamed'}</span>
            </div>
            <div className="history-meta mono">
              <span>{s.packet_count} pkts</span>
              <span>{new Date(s.started_at).toLocaleString()}</span>
              <button className="history-delete" onClick={(e) => handleDelete(s.id, e)}>×</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
