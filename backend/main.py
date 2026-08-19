"""
NetPulse backend — FastAPI app exposing:
  - WebSocket /ws/live      : streams classified packets + summary updates
  - POST /api/capture/start : starts a background live capture
  - POST /api/capture/stop  : stops the running capture
  - GET  /api/capture/status: whether a capture is running
  - GET  /api/summary       : current summary report
  - POST /api/pcap/analyze  : upload and analyze an offline .pcap file

Only run live capture on an interface/network you own or are
authorized to monitor.
"""

import asyncio
import threading
import tempfile
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from capture_engine import PacketCapture
from websocket_manager import manager

app = FastAPI(title="NetPulse", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this to your frontend origin in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Global capture state -------------------------------------------------
capture = PacketCapture()
capture_thread: threading.Thread | None = None
main_loop: asyncio.AbstractEventLoop | None = None


def _on_packet(packet_info: dict):
    """Called from the sniff background thread — hop back onto the
    asyncio event loop to broadcast over WebSocket."""
    if main_loop is None:
        return
    asyncio.run_coroutine_threadsafe(
        manager.broadcast({"type": "packet", "data": packet_info}),
        main_loop,
    )


def _on_summary(summary: dict):
    if main_loop is None:
        return
    asyncio.run_coroutine_threadsafe(
        manager.broadcast({"type": "summary", "data": summary}),
        main_loop,
    )


@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_event_loop()
    capture.on_packet = _on_packet
    capture.on_summary = _on_summary


class CaptureStartRequest(BaseModel):
    iface: str | None = None
    bpf_filter: str | None = None
    count: int = 0  # 0 = unlimited


@app.post("/api/capture/start")
async def start_capture(req: CaptureStartRequest):
    global capture_thread

    if capture.running:
        raise HTTPException(status_code=409, detail="Capture already running")

    capture_thread = threading.Thread(
        target=capture.start,
        kwargs={"iface": req.iface, "bpf_filter": req.bpf_filter, "count": req.count},
        daemon=True,
    )
    capture_thread.start()
    return {"status": "started", "iface": req.iface, "filter": req.bpf_filter}


@app.post("/api/capture/stop")
async def stop_capture():
    if not capture.running:
        raise HTTPException(status_code=409, detail="No capture running")
    capture.stop()
    return {"status": "stopping"}


@app.get("/api/capture/status")
async def capture_status():
    return {"running": capture.running, "packet_count": capture.packet_count}


@app.get("/api/summary")
async def get_summary():
    return capture.generate_summary()


@app.post("/api/pcap/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(".pcap") and not file.filename.endswith(".pcapng"):
        raise HTTPException(status_code=400, detail="File must be .pcap or .pcapng")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        offline_capture = PacketCapture(on_packet=_on_packet, on_summary=_on_summary)
        report = offline_capture.analyze_pcap(tmp_path)
        return report
    finally:
        os.unlink(tmp_path)


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # send current status immediately on connect
        await websocket.send_json({
            "type": "status",
            "data": {"running": capture.running, "packet_count": capture.packet_count},
        })
        while True:
            # We don't expect inbound messages, but keep the connection
            # alive and allow the client to ping.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
