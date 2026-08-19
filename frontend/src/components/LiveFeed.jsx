const PROTOCOL_COLOR = {
  HTTP: '#4FD1C5',
  DNS: '#B79CED',
  TLS: '#E8A33D',
  ICMP: '#F27059',
  TCP: '#7A8CA3',
  UDP: '#7A8CA3',
}

function describe(pkt) {
  if (pkt.protocol === 'HTTP' && pkt.http_method) {
    return `${pkt.http_method} ${pkt.http_host ?? ''}${pkt.http_path ?? ''}`
  }
  if (pkt.protocol === 'HTTP' && pkt.http_status) {
    return `${pkt.http_status} ${pkt.http_reason ?? ''}`
  }
  if (pkt.protocol === 'DNS' && pkt.dns_query) {
    return `${pkt.dns_query} (${pkt.dns_qtype ?? '?'})`
  }
  if (pkt.protocol === 'TLS' && pkt.sni) {
    return `SNI ${pkt.sni}`
  }
  if (pkt.protocol === 'TLS' && pkt.tls_type) {
    return pkt.tls_type
  }
  if (pkt.protocol === 'ICMP') {
    return pkt.icmp_type ?? ''
  }
  if (pkt.flags) {
    return `flags=${pkt.flags}`
  }
  return ''
}

export default function LiveFeed({ packets }) {
  return (
    <div className="panel feed-panel">
      <div className="panel-header">
        <span className="eyebrow">Live feed</span>
        <h2>Packet stream</h2>
      </div>
      <div className="feed-table">
        <div className="feed-row feed-row-head">
          <span>Proto</span>
          <span>Source</span>
          <span>Destination</span>
          <span>Detail</span>
        </div>
        <div className="feed-body">
          {packets.length === 0 && (
            <div className="feed-empty">No packets yet — start a capture to see live traffic.</div>
          )}
          {packets.map((pkt) => (
            <div className="feed-row" key={pkt.id}>
              <span
                className="proto-tag"
                style={{ color: PROTOCOL_COLOR[pkt.protocol] ?? '#7A8CA3' }}
              >
                {pkt.protocol}
              </span>
              <span className="mono">{pkt.source}{pkt.source_port ? `:${pkt.source_port}` : ''}</span>
              <span className="mono">{pkt.destination}{pkt.destination_port ? `:${pkt.destination_port}` : ''}</span>
              <span className="detail">{describe(pkt)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
