const PROTOCOL_COLOR = {
  HTTP: '#4FD1C5',
  DNS: '#B79CED',
  TLS: '#E8A33D',
  ICMP: '#F27059',
  TCP: '#7A8CA3',
  UDP: '#5C6B7F',
  OTHER: '#3d4552',
}

export default function ProtocolStats({ summary }) {
  const counts = summary?.protocol_counts ?? {}
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="eyebrow">Breakdown</span>
        <h2>Protocol mix</h2>
      </div>
      <div className="stat-bars">
        {Object.entries(counts)
          .filter(([, v]) => v > 0)
          .sort((a, b) => b[1] - a[1])
          .map(([proto, count]) => (
            <div className="stat-row" key={proto}>
              <div className="stat-label">
                <span>{proto}</span>
                <span className="mono">{count}</span>
              </div>
              <div className="stat-track">
                <div
                  className="stat-fill"
                  style={{
                    width: `${(count / total) * 100}%`,
                    background: PROTOCOL_COLOR[proto] ?? '#5C6B7F',
                  }}
                />
              </div>
            </div>
          ))}
        {Object.values(counts).every((v) => v === 0) && (
          <div className="feed-empty">Waiting for traffic...</div>
        )}
      </div>
    </div>
  )
}
