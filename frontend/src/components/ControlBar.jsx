import { useState, useRef } from 'react'

export default function ControlBar({ running, connected, packetCount, onStart, onStop, onAnalyzePcap }) {
  const [iface, setIface] = useState('')
  const [bpfFilter, setBpfFilter] = useState('tcp or udp or icmp')
  const [busy, setBusy] = useState(false)
  const fileInputRef = useRef(null)

  const handleStart = async () => {
    setBusy(true)
    try {
      await onStart({ iface: iface || null, bpfFilter: bpfFilter || null })
    } finally {
      setBusy(false)
    }
  }

  const handleStop = async () => {
    setBusy(true)
    try {
      await onStop()
    } finally {
      setBusy(false)
    }
  }

  const handleFile = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setBusy(true)
    try {
      await onAnalyzePcap(file)
    } finally {
      setBusy(false)
      e.target.value = ''
    }
  }

  return (
    <div className="control-bar">
      <div className="control-group">
        <span className={`status-dot ${connected ? 'status-live' : 'status-off'}`} />
        <span className="control-status">
          {connected ? (running ? 'Capturing' : 'Connected · idle') : 'Disconnected'}
        </span>
        <span className="mono packet-count">{packetCount.toLocaleString()} packets</span>
      </div>

      <div className="control-group control-inputs">
        <input
          className="control-input"
          placeholder="interface (blank = default)"
          value={iface}
          onChange={(e) => setIface(e.target.value)}
          disabled={running}
        />
        <input
          className="control-input control-input-wide"
          placeholder="BPF filter"
          value={bpfFilter}
          onChange={(e) => setBpfFilter(e.target.value)}
          disabled={running}
        />
      </div>

      <div className="control-group">
        {!running ? (
          <button className="btn btn-primary" onClick={handleStart} disabled={busy || !connected}>
            Start capture
          </button>
        ) : (
          <button className="btn btn-stop" onClick={handleStop} disabled={busy}>
            Stop capture
          </button>
        )}
        <button
          className="btn btn-secondary"
          onClick={() => fileInputRef.current?.click()}
          disabled={busy}
        >
          Analyze .pcap
        </button>
        <input
          type="file"
          accept=".pcap,.pcapng"
          ref={fileInputRef}
          style={{ display: 'none' }}
          onChange={handleFile}
        />
      </div>
    </div>
  )
}
