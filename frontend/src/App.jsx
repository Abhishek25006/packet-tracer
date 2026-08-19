import { useState, useCallback } from 'react'
import { useLiveSocket } from './hooks/useLiveSocket'
import PulseHeader from './components/PulseHeader'
import ControlBar from './components/ControlBar'
import LiveFeed from './components/LiveFeed'
import ProtocolStats from './components/ProtocolStats'
import HandshakePanel from './components/HandshakePanel'
import AnomalyPanel from './components/AnomalyPanel'
import HistoryPanel from './components/HistoryPanel'
import SessionDetail from './components/SessionDetail'

export default function App() {
  const {
    connected,
    running,
    packetCount,
    feed,
    summary,
    throughput,
    startCapture,
    stopCapture,
    analyzePcap,
  } = useLiveSocket()

  const [historyRefreshKey, setHistoryRefreshKey] = useState(0)
  const [selectedSessionId, setSelectedSessionId] = useState(null)

  // Bump the history refresh key whenever a capture stops or a pcap
  // finishes analyzing, so the History panel picks up the new session.
  const wrappedStop = useCallback(async () => {
    const res = await stopCapture()
    setTimeout(() => setHistoryRefreshKey((k) => k + 1), 800)
    return res
  }, [stopCapture])

  const wrappedAnalyzePcap = useCallback(async (file) => {
    const res = await analyzePcap(file)
    setHistoryRefreshKey((k) => k + 1)
    return res
  }, [analyzePcap])

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">◈</span>
          <div>
            <h1>NetPulse</h1>
            <p className="brand-sub">Real-time network packet analysis</p>
          </div>
        </div>
        <PulseHeader throughput={throughput} running={running} connected={connected} />
      </header>

      <ControlBar
        running={running}
        connected={connected}
        packetCount={packetCount}
        onStart={startCapture}
        onStop={wrappedStop}
        onAnalyzePcap={wrappedAnalyzePcap}
      />

      <main className="dashboard-grid">
        <LiveFeed packets={feed} />
        <div className="side-column">
          <ProtocolStats summary={summary} />
          <HandshakePanel summary={summary} />
          <AnomalyPanel summary={summary} />
        </div>
      </main>

      <section className="history-section">
        <HistoryPanel refreshKey={historyRefreshKey} onSelectSession={setSelectedSessionId} />
      </section>

      <SessionDetail sessionId={selectedSessionId} onClose={() => setSelectedSessionId(null)} />

      <footer className="app-footer">
        Authorized monitoring only — run captures solely on networks and interfaces you own or have explicit permission to observe.
      </footer>
    </div>
  )
}
