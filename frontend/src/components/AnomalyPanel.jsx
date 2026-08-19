export default function AnomalyPanel({ summary }) {
  const dnsAnomalies = summary?.dns_anomalies ?? []
  const pingSweeps = summary?.ping_sweep_candidates ?? []
  const tlsHosts = summary?.tls_hosts_seen ?? []

  const hasFlags = dnsAnomalies.length > 0 || pingSweeps.length > 0

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="eyebrow">Triage</span>
        <h2>Flags &amp; visibility</h2>
      </div>

      {!hasFlags && (
        <div className="ok-banner">No anomalies flagged in this window.</div>
      )}

      {dnsAnomalies.length > 0 && (
        <div className="flag-group">
          <span className="eyebrow warn">Unusual DNS query volume</span>
          {dnsAnomalies.map((ip) => (
            <div className="mono flag-row" key={ip}>{ip}</div>
          ))}
        </div>
      )}

      {pingSweeps.length > 0 && (
        <div className="flag-group">
          <span className="eyebrow warn">Ping sweep candidates</span>
          {pingSweeps.map((ip) => (
            <div className="mono flag-row" key={ip}>{ip}</div>
          ))}
        </div>
      )}

      {tlsHosts.length > 0 && (
        <div className="flag-group">
          <span className="eyebrow">TLS hosts seen (via SNI)</span>
          <div className="sni-chips">
            {tlsHosts.slice(0, 12).map((host) => (
              <span className="sni-chip mono" key={host}>{host}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
