import asyncio
import logging
import json
from contextlib import asynccontextmanager
from collections import defaultdict
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from config import CHANNELS, POLL_INTERVAL
from reading.log_reader       import read_logs
from normalization.normalizer  import normalize
from detection.detector        import detect
from scoring.scorer            import calculate_score
from db.database               import init_db, save_alert, get_alerts, get_stats, clear_alerts
from alerts.alert_manager      import alert_manager
from notifications.email_notifier import send_critical_alert

logger = logging.getLogger("ids.main")

# Track last seen RecordNumber per channel
last_record = defaultdict(int)

# ── Background Polling Loop ───────────────
async def poll_logs():
    """
    Runs forever in background task.
    Reads ONLY NEW logs, processes them and stores alerts.
    """
    logger.info("Background polling started...")

    while True:
        for channel in CHANNELS:
            try:
                # Read only new events since last poll
                logs = read_logs(channel, after_record=last_record[channel])

                for log in logs:
                    rid = log.get("record_id", 0)

                    # Full pipeline
                    clean    = normalize(log)
                    detected = detect(clean)
                    scored   = calculate_score(detected)

                    # Send ALL events to WebSocket for real-time display
                    await alert_manager.dispatch(scored)

                    # Only store suspicious events in database
                    if scored["is_suspicious"]:
                        # Prepare alert object
                        alert_data = {
                            "event_id":    scored["event_id"],
                            "description": scored["description"],
                            "username":    scored["username"],
                            "ip_address":  scored["ip_address"],
                            "computer":    scored["computer"],
                            "channel":     scored["channel"],
                            "source":      scored["source"],
                            "time":        scored["time"],
                            "risk_level":  scored["risk_level"],
                            "severity":    scored["severity"],
                            "risk_score":  scored["risk_score"],
                            "reason":      scored["reason"],
                            "mitigation":  scored.get("mitigation", ""),
                            "raw_data":    json.dumps(scored.get("raw_data", []))
                        }
                        
                        # save_alert returns True if inserted (not duplicate)
                        if save_alert(alert_data):
                            await alert_manager.dispatch(alert_data)
                    
                    # Now that log is processed, update last_record
                    if rid > last_record[channel]:
                        last_record[channel] = rid

            except Exception as e:
                logger.error(f"{channel}: {e}", exc_info=True)

        await asyncio.sleep(POLL_INTERVAL)


async def handle_email_alerts(alert):
    """
    Subscriber callback to send emails for critical alerts
    """
    if alert.get("severity") == "CRITICAL":
        send_critical_alert(alert)


# ── Lifespan (Startup/Shutdown) ───────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing Database...")
    init_db()
    
    # Start polling task
    polling_task = asyncio.create_task(poll_logs())
    logger.info("Polling task started ✅")
    
    # Register email notifier
    alert_manager.add_subscriber(handle_email_alerts)
    logger.info("Email notifier registered ✅")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    polling_task.cancel()


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
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/alerts")
async def api_get_alerts(limit: int = Query(100, ge=1, le=500)):
    alerts = get_alerts(limit)
    return alerts


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


# ── WebSocket for Live Alerts ─────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    logger.info("Client connected to WebSocket")
    
    # Define a callback that sends the alert via WebSocket
    async def send_alert(alert):
        try:
            await websocket.send_json({"type": "NEW_ALERT", "alert": alert})
        except Exception as e:
            # Log errors, but don't crash the server if one client fails
            logger.error(f"Error sending alert to client: {e}", exc_info=True)
            
    # Subscribe this connection to the alert manager
    alert_manager.add_subscriber(send_alert)
    
    try:
        # Keep connection open
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("Client disconnected from WebSocket")
    finally:
        alert_manager.remove_subscriber(send_alert)
