import { useEffect, useRef, useState, useCallback } from 'react'

const MAX_FEED_LENGTH = 200
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const WS_BASE = API_BASE.replace(/^http/, 'ws')

export function useLiveSocket() {
  const [connected, setConnected] = useState(false)
  const [running, setRunning] = useState(false)
  const [packetCount, setPacketCount] = useState(0)
  const [feed, setFeed] = useState([])
  const [summary, setSummary] = useState(null)
  const [throughput, setThroughput] = useState([])
  const wsRef = useRef(null)
  const countSinceTickRef = useRef(0)

  useEffect(() => {
    const url = `${WS_BASE}/ws/live`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'packet') {
        countSinceTickRef.current += 1
        setPacketCount((c) => c + 1)
        setFeed((prev) => {
          const next = [msg.data, ...prev]
          return next.length > MAX_FEED_LENGTH ? next.slice(0, MAX_FEED_LENGTH) : next
        })
      } else if (msg.type === 'summary') {
        setSummary(msg.data)
      } else if (msg.type === 'status') {
        setRunning(msg.data.running)
        setPacketCount(msg.data.packet_count)
      }
    }

    return () => ws.close()
  }, [])

  useEffect(() => {
    const interval = setInterval(() => {
      setThroughput((prev) => {
        const next = [...prev, countSinceTickRef.current]
        countSinceTickRef.current = 0
        return next.length > 60 ? next.slice(-60) : next
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const startCapture = useCallback(async (opts = {}) => {
    const res = await fetch(`${API_BASE}/api/capture/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface: opts.iface ?? null, bpf_filter: opts.bpfFilter ?? null, count: opts.count ?? 0 }),
    })
    if (res.ok) setRunning(true)
    return res
  }, [])

  const stopCapture = useCallback(async () => {
    const res = await fetch(`${API_BASE}/api/capture/stop`, { method: 'POST' })
    if (res.ok) setRunning(false)
    return res
  }, [])

  const analyzePcap = useCallback(async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    const res = await fetch(`${API_BASE}/api/pcap/analyze`, { method: 'POST', body: formData })
    if (res.ok) {
      const data = await res.json()
      setSummary(data)
    }
    return res
  }, [])

  return {
    connected,
    running,
    packetCount,
    feed,
    summary,
    throughput,
    startCapture,
    stopCapture,
    analyzePcap,
  }
}
