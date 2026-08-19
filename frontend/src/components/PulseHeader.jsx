import { useEffect, useRef } from 'react'

export default function PulseHeader({ throughput, running, connected }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const dpr = window.devicePixelRatio || 1
    const width = canvas.clientWidth
    const height = canvas.clientHeight
    canvas.width = width * dpr
    canvas.height = height * dpr
    ctx.scale(dpr, dpr)
    ctx.clearRect(0, 0, width, height)

    const max = Math.max(1, ...throughput, 5)
    const points = throughput.length ? throughput : new Array(60).fill(0)
    const stepX = width / (points.length - 1 || 1)

    // baseline grid
    ctx.strokeStyle = 'rgba(232, 163, 61, 0.08)'
    ctx.lineWidth = 1
    for (let i = 1; i < 4; i++) {
      const y = (height / 4) * i
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(width, y)
      ctx.stroke()
    }

    // pulse line
    ctx.beginPath()
    points.forEach((val, i) => {
      const x = i * stepX
      const y = height - (val / max) * (height * 0.82) - 4
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    })
    ctx.strokeStyle = connected && running ? '#E8A33D' : '#5a5346'
    ctx.lineWidth = 2
    ctx.shadowColor = connected && running ? 'rgba(232, 163, 61, 0.6)' : 'transparent'
    ctx.shadowBlur = 8
    ctx.stroke()
    ctx.shadowBlur = 0

    // leading dot
    if (points.length) {
      const lastX = (points.length - 1) * stepX
      const lastY = height - (points[points.length - 1] / max) * (height * 0.82) - 4
      ctx.beginPath()
      ctx.arc(lastX, lastY, 3, 0, Math.PI * 2)
      ctx.fillStyle = connected && running ? '#E8A33D' : '#5a5346'
      ctx.fill()
    }
  }, [throughput, running, connected])

  return (
    <div className="pulse-header">
      <canvas ref={canvasRef} className="pulse-canvas" />
    </div>
  )
}
