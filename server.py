"""
ISEA — FastAPI Web Server

Exposes the forensic analysis engine as a B2B SaaS web application.
Real-time scan events via WebSocket, agent streaming via SSE.

Start:  uvicorn server:app --reload --port 8000
"""

import asyncio
import json
import os
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from config import config
from core.cluster_scanner import ClusterScanner, ScanResult

# ------------------------------------------------------------------ #
# App setup
# ------------------------------------------------------------------ #

app = FastAPI(title="ISEA — Intelligent Storage Evidence Analyzer", version="1.0.0")

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# ------------------------------------------------------------------ #
# In-memory state (replace with DB for multi-tenant production)
# ------------------------------------------------------------------ #

_pending_scans: dict[str, dict] = {}     # scan_id → {path, filename, cluster_size, step}
_scan_results:  dict[str, ScanResult] = {}
_agent_sessions: dict[str, Any] = {}     # scan_id → ForensicAgent
_scan_history:  list[dict] = []          # for dashboard table


# ------------------------------------------------------------------ #
# Disk persistence helpers — scan metadata survives server restarts
# ------------------------------------------------------------------ #

def _meta_path(scan_id: str) -> Path:
    return UPLOAD_DIR / scan_id / "scan_meta.json"


def _save_scan_meta(scan_id: str, meta: dict) -> None:
    """Persist scan metadata to disk so it survives server reloads."""
    try:
        path = _meta_path(scan_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(meta), encoding="utf-8")
    except Exception as e:
        import sys
        print(f"ERROR saving scan meta: {repr(e)}", file=sys.stderr)


def _load_scan_meta(scan_id: str) -> dict | None:
    """Load scan metadata from disk (fallback when not in memory)."""
    try:
        path = _meta_path(scan_id)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _get_pending(scan_id: str) -> dict | None:
    """Get pending scan — from memory first, then disk."""
    if scan_id in _pending_scans:
        return _pending_scans[scan_id]
    meta = _load_scan_meta(scan_id)
    if meta:
        _pending_scans[scan_id] = meta  # re-hydrate in-memory cache
    return meta


def _load_all_pending_from_disk() -> None:
    """On startup, reload any scan metadata written before a server restart."""
    if not UPLOAD_DIR.exists():
        return
    for meta_file in UPLOAD_DIR.glob("*/scan_meta.json"):
        try:
            scan_id = meta_file.parent.name
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            _pending_scans[scan_id] = meta
        except Exception:
            pass


_load_all_pending_from_disk()


# ------------------------------------------------------------------ #
# Pages
# ------------------------------------------------------------------ #

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    total_scans = len(_scan_history)
    total_wipe_regions = sum(h.get("wipe_regions", 0) for h in _scan_history)
    avg_score = (
        sum(h.get("evidence_score", 0) for h in _scan_history) / total_scans
        if total_scans else 0
    )
    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_scans": total_scans,
        "total_wipe_regions": total_wipe_regions,
        "avg_score": round(avg_score, 1),
        "recent_scans": list(reversed(_scan_history))[:20],
    })


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_page(request: Request, scan_id: str):
    pending = _get_pending(scan_id)
    if not pending:
        return HTMLResponse("<h1>Scan not found</h1>", status_code=404)
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "scan_id": scan_id,
        "filename": pending["filename"],
        "size_mb": pending["size_mb"],
    })


@app.get("/results/{scan_id}", response_class=HTMLResponse)
async def results_page(request: Request, scan_id: str):
    result = _scan_results.get(scan_id)
    if not result:
        return HTMLResponse("<h1>Results not found. Scan may still be running.</h1>", status_code=404)
    return templates.TemplateResponse("results.html", {
        "request": request,
        "scan_id": scan_id,
        "result": result.to_dict(),
        "filename": (_get_pending(scan_id) or {}).get("filename", "Unknown"),
    })


@app.get("/chat/{scan_id}", response_class=HTMLResponse)
async def chat_page(request: Request, scan_id: str):
    result = _scan_results.get(scan_id)
    if not result:
        return HTMLResponse("<h1>Results not found.</h1>", status_code=404)
    pending = _get_pending(scan_id)
    scanner = ClusterScanner(pending["path"] if pending else "")
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "scan_id": scan_id,
        "filename": (pending or {}).get("filename", "Unknown"),
        "summary": scanner.get_summary(result),
        "risk_level": result.intent_assessment.get("risk_level", "MINIMAL"),
        "evidence_score": result.evidence_score,
    })


# ------------------------------------------------------------------ #
# API: Upload
# ------------------------------------------------------------------ #

@app.post("/api/upload")
async def upload_image(
    file: UploadFile = File(...),
    cluster_size: int = Form(4096),
    step: int = Form(1),
):
    scan_id = str(uuid.uuid4())[:8]
    save_dir = UPLOAD_DIR / scan_id
    save_dir.mkdir(parents=True, exist_ok=True)
    save_path = save_dir / file.filename

    async with aiofiles.open(save_path, "wb") as f:
        content = await file.read()
        await f.write(content)

    size_mb = round(len(content) / (1024 * 1024), 2)
    meta = {
        "path": str(save_path),
        "filename": file.filename,
        "size_mb": size_mb,
        "cluster_size": int(cluster_size),
        "step": int(step),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }
    _pending_scans[scan_id] = meta
    _save_scan_meta(scan_id, meta)  # persist to disk — survives server reload
    return {"scan_id": scan_id, "filename": file.filename, "size_mb": size_mb}


# ------------------------------------------------------------------ #
# SSE: Real-time scan streaming
# ------------------------------------------------------------------ #

@app.get("/api/scan/{scan_id}/stream")
async def scan_stream(scan_id: str, request: Request):
    """SSE endpoint — streams scan progress events to the browser."""
    pending = _pending_scans.get(scan_id)
    if not pending:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    # If already completed, just return the result immediately
    if scan_id in _scan_results:
        result = _scan_results[scan_id]

        async def already_done():
            complete_evt = {
                "type": "complete",
                "evidence_score": result.evidence_score,
                "risk_level": result.intent_assessment.get("risk_level", "MINIMAL"),
                "wipe_count": len(result.wipe_detections),
                "tool": (result.signature_matches[0].get("tool", "Unknown")
                         if result.signature_matches else "None detected"),
                "redirect_url": f"/results/{scan_id}",
            }
            yield f"data: {json.dumps(complete_evt)}\n\n"

        return StreamingResponse(already_done(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    loop = asyncio.get_running_loop()
    event_queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
    sentinel = object()

    batch_state = {
        "counter": 0,
        "counts": {"natural_residual": 0, "os_clear": 0, "intentional_wipe": 0, "secure_erase": 0},
    }
    BATCH_SIZE = 50

    def on_progress(current: int, total: int):
        loop.call_soon_threadsafe(
            event_queue.put_nowait,
            {"type": "progress", "current": current, "total": total,
             "pct": round(current / total * 100, 1) if total else 0}
        )

    def on_cluster_event(cluster_id: int, analysis: dict):
        cls = analysis.get("classification", "natural_residual")
        entropy = analysis.get("entropy", 0.0)
        batch_state["counter"] += 1
        batch_state["counts"][cls] = batch_state["counts"].get(cls, 0) + 1

        if batch_state["counter"] % BATCH_SIZE == 0:
            loop.call_soon_threadsafe(
                event_queue.put_nowait,
                {
                    "type": "cluster_batch",
                    "counts": dict(batch_state["counts"]),
                    "entropy": round(entropy, 3),
                    "cluster_id": cluster_id,
                }
            )

    result_holder: list[ScanResult] = []

    def run_scan():
        try:
            scanner = ClusterScanner(
                image_path=pending["path"],
                cluster_size=pending["cluster_size"],
                progress_callback=on_progress,
                cluster_event_callback=on_cluster_event,
            )
            result = scanner.run_full_scan(step=pending["step"])
            result_holder.append(result)
            loop.call_soon_threadsafe(event_queue.put_nowait, {"type": "__done__", "result": result})
        except Exception as exc:
            loop.call_soon_threadsafe(event_queue.put_nowait, {"type": "__error__", "message": str(exc)})
        finally:
            loop.call_soon_threadsafe(event_queue.put_nowait, sentinel)

    async def generate():
        # Send started event immediately
        path = Path(pending["path"])
        total_clusters = path.stat().st_size // pending["cluster_size"]
        started = {
            "type": "started",
            "scan_id": scan_id,
            "filename": pending["filename"],
            "size_mb": pending["size_mb"],
            "total_clusters": total_clusters,
            "cluster_size": pending["cluster_size"],
            "step": pending["step"],
        }
        yield f"data: {json.dumps(started)}\n\n"

        # Start scan in background thread
        t = threading.Thread(target=run_scan, daemon=True)
        t.start()

        # Stream events
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=120.0)
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"
                continue

            if event is sentinel:
                break

            if event["type"] == "__done__":
                result = event["result"]
                _scan_results[scan_id] = result

                for det in result.wipe_detections:
                    yield f"data: {json.dumps({'type': 'wipe_detected', 'detection': det.to_dict()})}\n\n"

                complete_evt = {
                    "type": "complete",
                    "evidence_score": result.evidence_score,
                    "risk_level": result.intent_assessment.get("risk_level", "MINIMAL"),
                    "wipe_count": len(result.wipe_detections),
                    "tool": (result.signature_matches[0].get("tool", "Unknown")
                             if result.signature_matches else "None detected"),
                    "redirect_url": f"/results/{scan_id}",
                }
                yield f"data: {json.dumps(complete_evt)}\n\n"

                _scan_history.append({
                    "scan_id": scan_id,
                    "filename": pending["filename"],
                    "size_mb": pending["size_mb"],
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                    "evidence_score": result.evidence_score,
                    "risk_level": result.intent_assessment.get("risk_level", "MINIMAL"),
                    "wipe_regions": len(result.wipe_detections),
                })

            elif event["type"] == "__error__":
                yield f"data: {json.dumps({'type': 'error', 'message': event['message']})}\n\n"

            else:
                yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ------------------------------------------------------------------ #
# API: SSE scan stream (used by scan.html)
# ------------------------------------------------------------------ #

@app.get("/api/scan/{scan_id}/stream")
async def scan_stream(scan_id: str, request: Request):
    pending = _get_pending(scan_id)
    if not pending:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    loop = asyncio.get_running_loop()
    
    is_new_scan = False
    if scan_id in _active_scans:
        event_queue = _active_scans[scan_id]
        print(f"[{datetime.now().time()}] Reconnected SSE for scan {scan_id}", file=sys.stderr)
    else:
        event_queue = asyncio.Queue(maxsize=0)
        _active_scans[scan_id] = event_queue
        is_new_scan = True
        print(f"[{datetime.now().time()}] Started new SSE stream for scan {scan_id}", file=sys.stderr)

    batch_state = {
        "counter": 0,
        "counts": {"natural_residual": 0, "os_clear": 0, "intentional_wipe": 0, "secure_erase": 0},
        "last_entropy": 0.0,
        "last_pct": -1.0,
    }
    BATCH_SIZE = 50

    def on_progress(current: int, total: int):
        pct = round(current / total * 100, 1) if total else 0.0
        if pct != batch_state.get("last_pct"):
            batch_state["last_pct"] = pct
            loop.call_soon_threadsafe(
                event_queue.put_nowait,
                {"type": "progress", "current": current, "total": total, "pct": pct}
            )

    def on_cluster_event(cluster_id: int, analysis: dict):
        cls = analysis.get("classification", "natural_residual")
        entropy = analysis.get("entropy", 0.0)
        batch_state["counter"] += 1
        batch_state["counts"][cls] = batch_state["counts"].get(cls, 0) + 1
        batch_state["last_entropy"] = entropy
        if batch_state["counter"] % BATCH_SIZE == 0:
            loop.call_soon_threadsafe(
                event_queue.put_nowait,
                {
                    "type": "cluster_batch",
                    "counts": dict(batch_state["counts"]),
                    "entropy": round(entropy, 3),
                    "cluster_id": cluster_id,
                }
            )

    result_holder: list[ScanResult] = []
    error_holder: list[str] = []

    def run_scan():
        try:
            scanner = ClusterScanner(
                image_path=pending["path"],
                cluster_size=pending["cluster_size"],
                progress_callback=on_progress,
                cluster_event_callback=on_cluster_event,
            )
            # Notify UI that cluster scan is done and post-processing started
            loop.call_soon_threadsafe(event_queue.put_nowait, {"type": "status", "message": "Finalizing analysis..."})
            result = scanner.run_full_scan(step=pending["step"])
            result_holder.append(result)
            loop.call_soon_threadsafe(event_queue.put_nowait, {"type": "__done__", "result": result})
        except Exception as exc:
            tb = traceback.format_exc()
            print(f"[Scan Thread Error] {scan_id}:\n{tb}", file=sys.stderr)
            error_holder.append(str(exc))
            loop.call_soon_threadsafe(event_queue.put_nowait, {"type": "__error__", "message": str(exc)})
        finally:
            loop.call_soon_threadsafe(_active_scans.pop, scan_id, None)

    async def generate():
        # Send the "started" event first
        try:
            path = Path(pending["path"])
            total_clusters = path.stat().st_size // pending["cluster_size"]
            started = {
                "type": "started",
                "scan_id": scan_id,
                "filename": pending["filename"],
                "size_mb": pending["size_mb"],
                "total_clusters": total_clusters,
                "cluster_size": pending["cluster_size"],
                "step": pending["step"],
            }
            yield f"data: {json.dumps(started)}\n\n"
        except Exception:
            pass

        # Start scan in background thread ONLY if this is a new scan
        if is_new_scan:
            scan_thread = threading.Thread(target=run_scan, daemon=True)
            scan_thread.start()

        wipe_detections_sent = 0
        while True:
            if await request.is_disconnected():
                break
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a heartbeat comment to keep the connection alive
                yield ": heartbeat\n\n"
                continue

            if event["type"] == "__done__":
                result = result_holder[0]
                _scan_results[scan_id] = result

                # Emit any pending wipe detections
                new_detections = result.wipe_detections[wipe_detections_sent:]
                for det in new_detections:
                    payload = {"type": "wipe_detected", "detection": det.to_dict()}
                    yield f"data: {json.dumps(payload)}\n\n"

                complete = {
                    "type": "complete",
                    "evidence_score": result.evidence_score,
                    "risk_level": result.intent_assessment.get("risk_level", "MINIMAL"),
                    "wipe_count": len(result.wipe_detections),
                    "tool": (result.signature_matches[0].get("tool", "Unknown")
                             if result.signature_matches else "None detected"),
                    "redirect_url": f"/results/{scan_id}",
                }
                yield f"data: {json.dumps(complete)}\n\n"

                _scan_history.append({
                    "scan_id": scan_id,
                    "filename": pending["filename"],
                    "size_mb": pending["size_mb"],
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                    "evidence_score": result.evidence_score,
                    "risk_level": result.intent_assessment.get("risk_level", "MINIMAL"),
                    "wipe_regions": len(result.wipe_detections),
                })
                break

            elif event["type"] == "__error__":
                err = {"type": "error", "message": event["message"]}
                yield f"data: {json.dumps(err)}\n\n"
                break

            else:
                yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ------------------------------------------------------------------ #
# API: Results
# ------------------------------------------------------------------ #

@app.get("/api/results/{scan_id}")
async def get_results(scan_id: str):
    result = _scan_results.get(scan_id)
    if not result:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return result.to_dict()


# ------------------------------------------------------------------ #
# API: Chat (SSE streaming)
# ------------------------------------------------------------------ #

@app.get("/api/chat/{scan_id}/stream")
async def chat_stream(scan_id: str, message: str, request: Request):
    result = _scan_results.get(scan_id)
    if not result:
        return JSONResponse({"error": "Scan results not found"}, status_code=404)

    # Get or create agent
    if scan_id not in _agent_sessions:
        try:
            config.validate()
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        from agent.forensic_agent import ForensicAgent
        from groq import Groq
        scanner = ClusterScanner(_pending_scans[scan_id]["path"])
        groq_client = Groq(api_key=config.groq_api_key)
        _agent_sessions[scan_id] = ForensicAgent(result, scanner, groq_client)

    agent = _agent_sessions[scan_id]

    async def generate():
        yield f"data: {json.dumps({'type': 'thinking'})}\n\n"

        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        sentinel = object()
        loop = asyncio.get_running_loop()

        def run_agent():
            try:
                for token in agent.stream_chat(message):
                    loop.call_soon_threadsafe(queue.put_nowait, token)
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, f"\n\n*Error: {exc}*")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, sentinel)

        t = threading.Thread(target=run_agent, daemon=True)
        t.start()

        first_token = True
        while True:
            item = await queue.get()
            if item is sentinel:
                break
            if first_token:
                yield f"data: {json.dumps({'type': 'start'})}\n\n"
                first_token = False
            yield f"data: {json.dumps({'type': 'token', 'token': item})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ------------------------------------------------------------------ #
# API: Report downloads
# ------------------------------------------------------------------ #

@app.get("/api/report/{scan_id}/json")
async def download_json_report(scan_id: str):
    result = _scan_results.get(scan_id)
    if not result:
        return JSONResponse({"error": "Not found"}, status_code=404)
    from agent.report_generator import ReportGenerator
    report_json = ReportGenerator(result).to_json()
    report_path = REPORT_DIR / f"isea_report_{scan_id}.json"
    report_path.write_text(report_json, encoding="utf-8")
    return FileResponse(
        path=str(report_path),
        filename=f"isea_report_{scan_id}.json",
        media_type="application/json",
    )


@app.get("/api/report/{scan_id}/markdown")
async def download_md_report(scan_id: str):
    result = _scan_results.get(scan_id)
    if not result:
        return JSONResponse({"error": "Not found"}, status_code=404)
    from agent.report_generator import ReportGenerator
    report_md = ReportGenerator(result).to_markdown()
    report_path = REPORT_DIR / f"isea_report_{scan_id}.md"
    report_path.write_text(report_md, encoding="utf-8")
    return FileResponse(
        path=str(report_path),
        filename=f"isea_report_{scan_id}.md",
        media_type="text/markdown",
    )


# ------------------------------------------------------------------ #
# Entry point
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print("\n  ISEA — Intelligent Storage Evidence Analyzer")
    print("  ─────────────────────────────────────────────")
    print(f"  Web UI: http://localhost:{port}\n")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
