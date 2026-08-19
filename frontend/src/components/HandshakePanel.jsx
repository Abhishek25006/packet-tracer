export default function HandshakePanel({ summary }) {
  const hs = summary?.tcp_handshakes
  const incomplete = summary?.incomplete_handshakes ?? []

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="eyebrow">TCP</span>
        <h2>Three-way handshake</h2>
      </div>

      <div className="handshake-diagram">
        <div className="hs-track">
          <span className="hs-node">CLIENT</span>
          <div className="hs-arrow hs-arrow-right"><span>SYN</span></div>
          <span className="hs-node">SERVER</span>
        </div>
        <div className="hs-track">
          <span className="hs-node hs-node-ghost" />
          <div className="hs-arrow hs-arrow-left"><span>SYN-ACK</span></div>
          <span className="hs-node hs-node-ghost" />
        </div>
        <div className="hs-track">
          <span className="hs-node hs-node-ghost" />
          <div className="hs-arrow hs-arrow-right"><span>ACK</span></div>
          <span className="hs-node hs-node-ghost" />
        </div>
      </div>

      {hs ? (
        <div className="hs-stats">
          <div><span className="mono">{hs.completed_handshakes}</span> completed</div>
          <div><span className="mono">{hs.incomplete_handshakes}</span> incomplete</div>
          <div>
            avg time{' '}
            <span className="mono">
              {hs.avg_total_handshake_ms != null ? `${hs.avg_total_handshake_ms} ms` : '—'}
            </span>
          </div>
        </div>
      ) : (
        <div className="feed-empty">No connections observed yet.</div>
      )}

      {incomplete.length > 0 && (
        <div className="incomplete-list">
          <span className="eyebrow warn">Possible SYN scan indicators</span>
          {incomplete.slice(0, 5).map((r, i) => (
            <div className="mono incomplete-row" key={i}>
              {r.client} → {r.server}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
