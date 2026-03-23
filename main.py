import asyncio
import logging
import json
from datetime import datetime
from contextlib import asynccontextmanager
from collections import defaultdict
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from config import CHANNELS, POLL_INTERVAL, REMOTE_DEVICES
from reading.log_reader       import read_logs
from reading.remote_reader    import remote_manager
from normalization.normalizer  import normalize
from detection.detector        import detect
from scoring.scorer            import calculate_score
from db.database               import init_db, save_alert, get_alerts, get_stats, clear_alerts
from alerts.alert_manager      import alert_manager, AlertManager

# Separate manager for broadcasting ALL logs (not just alerts)
log_manager = AlertManager()
from notifications.email_notifier import send_critical_alert

logger = logging.getLogger("ids.main")

# Track last seen RecordNumber per channel and device
last_record = defaultdict(int)
last_remote_record = defaultdict(lambda: defaultdict(int))

# ── Background Polling Loop ───────────────
async def poll_logs():
    """
    Runs forever in background task.
    Reads ONLY NEW logs from local and remote devices, processes them and stores alerts.
    """
    logger.info("Background polling started...")
    
    while True:
        try:
            logger.info("🔍 Polling for new logs...")
            new_logs_count = 0
            
            # Process local logs
            for channel in CHANNELS:
                try:
                    # Read logs with timeout
                    logger.debug(f"🔍 Polling local {channel}...")
                    logs = await asyncio.wait_for(
                        asyncio.to_thread(read_logs, channel, last_record[channel]),
                        timeout=30
                    )
                    
                    if logs:
                        logger.info(f"📂 Found {len(logs)} new logs in {channel}")
                        
                        batch_max_id = max((log.get("record_id", 0) for log in logs), default=0)
                        if batch_max_id > 0:
                            if batch_max_id < last_record[channel]:
                                logger.warning(f"🚨 LOCAL LOG CLEAR DETECTED: {channel}. Bookmark {last_record[channel]} -> {batch_max_id}")
                                last_record[channel] = batch_max_id
                            else:
                                last_record[channel] = max(last_record[channel], batch_max_id)
                        
                        for log in logs:
                            await process_log(log, "local")
                            new_logs_count += 1
                    else:
                        logger.debug(f"📂 No new logs in {channel}")

                except Exception as e:
                    logger.error(f"FAILED to poll local {channel}: {e}")

            # Process remote device logs
            for device in REMOTE_DEVICES:
                if not device.get("enabled", True):
                    continue
                    
                device_id = device["device_id"]
                try:
                    # Poll all channels for this device concurrently
                    async def poll_channel(chan):
                        try:
                            last_id = last_remote_record[device_id][chan]
                            # Read remote logs with timeout
                            return chan, await asyncio.wait_for(
                                asyncio.to_thread(remote_manager.read_logs, device_id, chan, last_id),
                                timeout=45
                            )
                        except asyncio.TimeoutError:
                            logger.error(f"⏰ TIMEOUT polling remote {device_id} ({chan})")
                            return chan, []

                    tasks = [poll_channel(c) for c in CHANNELS]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    # ... rest of remote processing unchanged ...
                    
                    for result in results:
                        if isinstance(result, Exception):
                            logger.error(f"Error polling remote channel: {result}")
                            continue
                        
                        channel, logs = result
                        if logs:
                            logger.info(f"🌐 Found {len(logs)} new logs from {device_id} {channel}")
                            
                            batch_max_id = max((log.get("record_id", 0) for log in logs), default=0)
                            if batch_max_id > 0:
                                current_bookmark = last_remote_record[device_id][channel]
                                if batch_max_id < current_bookmark:
                                    logger.warning(f"🚨 REMOTE LOG CLEAR DETECTED: {device_id} ({channel}). Bookmark {current_bookmark} -> {batch_max_id}")
                                    last_remote_record[device_id][channel] = batch_max_id
                                else:
                                    last_remote_record[device_id][channel] = max(current_bookmark, batch_max_id)
                            
                            for log in logs:
                                await process_log(log, "remote", device_id)
                                new_logs_count += 1
                        else:
                            logger.debug(f"🌐 No new logs from {device_id} {channel}")

                except Exception as e:
                    logger.error(f"FAILED to poll remote {device_id}: {e}")
            
            if new_logs_count > 0:
                logger.info(f"✅ Processed {new_logs_count} new logs this cycle")
            else:
                logger.debug("📭 No new logs found in this cycle")
                
        except Exception as e:
            logger.error(f"CRITICAL ERROR in polling loop: {e}")
        
        # Wait before next poll (configurable interval)
        from config import POLL_INTERVAL
        await asyncio.sleep(POLL_INTERVAL)


async def process_log(log, source_type="local", device_id=None):
    """Process a single log entry through the detection pipeline"""
    
    # Enrichment for normalization
    log["source_type"] = source_type
    if source_type == "remote" and device_id:
        log["device_id"] = device_id
    elif source_type == "local":
        import socket
        log["device_id"] = "local"
        log["device_name"] = socket.gethostname()
        try:
            log["device_ip"] = socket.gethostbyname(socket.gethostname())
        except:
            log["device_ip"] = "127.0.0.1"

    # Full pipeline
    clean    = normalize(log)
    detected = detect(clean)
    scored   = calculate_score(detected)

    # Add source information
    scored["source_type"] = source_type
    if source_type == "remote" and device_id:
        scored["device_id"] = device_id
        scored["device_name"] = log.get("device_name", "Unknown")
        scored["device_ip"] = log.get("device_ip", "Unknown")

    # Add computed severity and reason back into the raw log object
    log["severity"] = scored.get("severity", "INFO")
    log["risk_score"] = scored.get("risk_score", 0)
    log["reason"] = scored.get("reason", "")

    # Save every log to the logs table for the Unified Log View
    from db.database import save_log
    save_log(log)

    # Broadcast raw log to all WebSocket clients for real-time dashboard
    log_broadcast = {
        "record_id":   log.get("record_id"),
        "event_id":    log.get("event_id"),
        "channel":     log.get("channel"),
        "time":        log.get("time"),
        "computer":    log.get("computer"),
        "username":    log.get("username"),
        "ip_address":  log.get("ip_address"),
        "source":      log.get("source"),
        "message":     log.get("message", ""),
        "reason":      log.get("reason", ""),
        "device_id":   log.get("device_id", "local"),
        "device_name": log.get("device_name", ""),
        "source_type": source_type,
        "severity":    log["severity"],
        "risk_score":  log["risk_score"],
    }
    await log_manager.dispatch(log_broadcast)


    # Store ALL events in database (not just suspicious ones)
    # Prepare alert object for all events
    alert_data = {
        "event_id":    scored["event_id"],
        "description": scored["description"],
        "username":    scored["username"],
        "ip_address":  scored["ip_address"],
        "computer":    scored["computer"],
        "channel":     scored["channel"],
        "source":      scored["source"],
        "time":        scored["time"],
        "risk_level":  scored.get("severity", "INFO"),
        "severity":    scored["severity"],
        "risk_score":  scored["risk_score"],
        "reason":      scored["reason"],
        "mitigation":  scored.get("mitigation", ""),
        "raw_data":    json.dumps(scored.get("raw_data", [])),
        "source_type": source_type,
        "device_id":   device_id if source_type == "remote" else "local",
        "device_name": log.get("device_name") if source_type == "remote" else "Local System",
        "device_ip":   log.get("device_ip") if source_type == "remote" else "127.0.0.1"
    }
    
    # save_alert returns True if inserted (not duplicate)
    if save_alert(alert_data):
        # Only send WebSocket notifications for suspicious events
        if scored["is_suspicious"]:
            await alert_manager.dispatch(alert_data)


async def handle_email_alerts(alert):
    """
    Subscriber callback to send emails for critical alerts.
    Only sends emails for CRITICAL severity to avoid spam.
    """
    if alert.get("severity") == "CRITICAL":
        # send_critical_alert already spawns its own background thread
        send_critical_alert(alert)


# ── Lifespan (Startup/Shutdown) ───────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing Database...")
    init_db()
    
    # Pre-seed bookmarks from database
    from db.database import get_last_record_ids
    db_bookmarks = get_last_record_ids()
    for d_id, channels in db_bookmarks.items():
        if d_id == "local":
            for channel, rid in channels.items():
                last_record[channel] = rid
                logger.info(f"Seeded local {channel} bookmark: {rid}")
        else:
            for channel, rid in channels.items():
                last_remote_record[d_id][channel] = rid
                logger.info(f"Seeded remote {d_id} {channel} bookmark: {rid}")

    # Start polling task
    polling_task = asyncio.create_task(poll_logs())
    
    # Start cleanup task (runs every 5 minutes)
    async def cleanup_loop():
        while True:
            await asyncio.sleep(300)
            from db.database import cleanup_old_data
            cleanup_old_data(minutes=1440) # Keep 24 hours of history for charts
            
    cleanup_task = asyncio.create_task(cleanup_loop())
    logger.info("Background tasks started ✅")
    
    # Register email notifier
    alert_manager.add_subscriber(handle_email_alerts)
    
    async def dummy_subscriber(l):
        pass
    log_manager.add_subscriber(dummy_subscriber)  # keep manager active
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    polling_task.cancel()
    cleanup_task.cancel()


# ── App Definition ────────────────────────
app = FastAPI(title="IDS - Windows Log Monitor", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="frontend"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

# Restrict CORS in production, generic for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "DELETE"],
    allow_headers=["*"]
)

# ── Routes ────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Avoid stale HTML in browser after template/JS/CSS updates during development
    return templates.TemplateResponse(
        "index.html",
        {"request": request},
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@app.get("/api/alerts")
async def api_get_alerts(limit: int = Query(5000, ge=1, le=10000), window_minutes: int = Query(43200, ge=1, le=43200)):  # 30 days max
    alerts = get_alerts(limit, window_minutes)
    return alerts


@app.get("/api/logs")
async def api_get_logs(limit: int = Query(100, ge=1, le=1000), device_id: str = Query("all"), window_minutes: int = Query(60, ge=1, le=43200)):
    """Get raw logs for unified view"""
    from db.database import get_logs_with_window
    return get_logs_with_window(limit, device_id, window_minutes)


@app.get("/api/stats")
async def api_get_stats():
    return get_stats()


@app.delete("/api/alerts")
async def api_clear_alerts():
    clear_alerts()
    return {"status": "cleared"}


@app.get("/ping")
async def ping():
    stats = get_stats()
    return {"status": "IDS is running ✅", "alerts_stored": stats["total"]}


@app.get("/api/remote/devices")
async def get_remote_devices():
    """Get list of configured remote devices"""
    return {
        "devices": REMOTE_DEVICES,
        "total": len(REMOTE_DEVICES)
    }


@app.get("/api/remote/test/{device_id}")
async def test_remote_connection(device_id: str):
    """Test connection to a specific remote device"""
    success = remote_manager.test_connection(device_id)
    return {
        "device_id": device_id,
        "connection_status": "success" if success else "failed",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/remote/test-all")
async def test_all_remote_connections():
    """Test connections to all remote devices"""
    results = remote_manager.test_all_connections()
    return {
        "results": results,
        "total_devices": len(results),
        "successful_connections": sum(1 for success in results.values() if success),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/remote/logs/{device_id}")
async def get_remote_logs(device_id: str, channel: str = Query("Security"), limit: int = Query(20, ge=1, le=100)):
    """Get recent logs from a specific remote device"""
    logs = remote_manager.read_logs(device_id, channel, limit)
    return {
        "device_id": device_id,
        "channel": channel,
        "logs": logs,
        "count": len(logs)
    }


# ── WebSocket for Live Alerts + Logs ──────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    logger.info("Client connected to WebSocket")
    
    # Callback: send alert via WebSocket
    async def send_alert(alert):
        try:
            await websocket.send_json({"type": "NEW_ALERT", "alert": alert})
        except Exception as e:
            logger.error(f"Error sending alert to client: {e}")

    # Callback: send raw log via WebSocket
    async def send_log(log):
        try:
            await websocket.send_json({"type": "NEW_LOG", "log": log})
        except Exception as e:
            logger.error(f"Error sending log to client: {e}")

    # Send last 45 minutes of alert history on connection
    try:
        from db.database import get_alerts
        history = get_alerts(limit=100)
        history.sort(key=lambda x: x.get('time', ''), reverse=False)
        for alert in history:
            await send_alert(alert)
    except Exception as e:
        logger.error(f"Error sending history to WS: {e}")

    # Send recent logs for dashboard on connection
    try:
        from db.database import get_logs
        recent_logs = get_logs(limit=50, device_id=None)
        recent_logs.sort(key=lambda x: x.get('time', ''), reverse=False)
        for log in recent_logs:
            await send_log(log)
    except Exception as e:
        logger.error(f"Error sending log history to WS: {e}")

    # Subscribe this connection to both managers
    alert_manager.add_subscriber(send_alert)
    log_manager.add_subscriber(send_log)
    
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=300)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "PING"})
                except:
                    break
    except WebSocketDisconnect:
        logger.info("Client disconnected from WebSocket")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        alert_manager.remove_subscriber(send_alert)
        log_manager.remove_subscriber(send_log)
