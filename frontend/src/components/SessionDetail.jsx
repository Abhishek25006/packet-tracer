import { useEffect, useState } from 'react'

export default function SessionDetail({ sessionId, onClose }) {
  const [session, setSession] = useState(null)

  useEffect(() => {
    if (sessionId == null) return
    fetch(`/api/sessions/${sessionId}`)
      .then((res) => res.json())
      .then(setSession)
  }, [sessionId])

  if (sessionId == null) return null

  const summary = session?.summary

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span className="eyebrow">Session #{sessionId}</span>
            <h2>{session?.label || 'Loading...'}</h2>
          </div>
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>

        {!summary && <div className="feed-empty">Loading summary...</div>}

        {summary && (
          <div className="modal-body">
            <div className="hs-stats" style={{ marginBottom: 18 }}>
              <div>total <span className="mono">{summary.total_packets}</span></div>
              <div>
                handshakes{' '}
                <span className="mono">
                  {summary.tcp_handshakes?.completed_handshakes ?? 0} completed /{' '}
                  {summary.tcp_handshakes?.incomplete_handshakes ?? 0} incomplete
                </span>
              </div>
            </div>

            <div className="stat-bars">
              {Object.entries(summary.protocol_counts || {})
                .filter(([, v]) => v > 0)
                .map(([proto, count]) => (
                  <div className="stat-row" key={proto}>
                    <div className="stat-label">
                      <span>{proto}</span>
                      <span className="mono">{count}</span>
                    </div>
                  </div>
                ))}
            </div>

            {summary.tls_hosts_seen?.length > 0 && (
              <div className="flag-group" style={{ marginTop: 16 }}>
                <span className="eyebrow">TLS hosts seen</span>
                <div className="sni-chips">
                  {summary.tls_hosts_seen.map((h) => (
                    <span className="sni-chip mono" key={h}>{h}</span>
                  ))}
                </div>
              </div>
            )}

            {summary.incomplete_handshakes?.length > 0 && (
              <div className="incomplete-list">
                <span className="eyebrow warn">Possible SYN scan indicators</span>
                {summary.incomplete_handshakes.map((r, i) => (
                  <div className="mono incomplete-row" key={i}>{r.client} → {r.server}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
