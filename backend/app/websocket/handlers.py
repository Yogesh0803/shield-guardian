import asyncio
import uuid
import psutil
from datetime import datetime, timezone

from fastapi import WebSocket, WebSocketDisconnect

from app.websocket.manager import manager


def _get_real_network_stats():
    """Get real network usage from psutil."""
    counters = psutil.net_io_counters()
    return {
        "bytes_in": counters.bytes_recv,
        "bytes_out": counters.bytes_sent,
        "packets": counters.packets_recv + counters.packets_sent,
    }


def _get_real_connections():
    """Get real active connections from psutil."""
    connections = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "NONE" or not conn.laddr:
                continue

            # Get process name
            app_name = "unknown"
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    app_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            dst_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            dst_port = conn.raddr.port if conn.raddr else 0

            # Deduplicate
            key = (conn.laddr.ip, conn.laddr.port, dst_ip, dst_port)
            if key in seen:
                continue
            seen.add(key)

            # Map status
            status = conn.status
            if status not in ("ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", "LISTEN"):
                status = "ESTABLISHED"

            connections.append({
                "id": str(uuid.uuid4()),
                "endpoint": "localhost",
                "app": app_name,
                "status": status,
                "src_ip": conn.laddr.ip,
                "src_port": conn.laddr.port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": "TCP" if conn.type == 1 else "UDP",
            })

            if len(connections) >= 50:
                break
    except (psutil.AccessDenied, OSError):
        pass

    return connections


async def websocket_network_endpoint(websocket: WebSocket):
    """WebSocket handler for real-time network data."""
    await manager.connect(websocket, "network")

    # Per-connection state — each client tracks its own deltas.
    prev_stats = await asyncio.to_thread(_get_real_network_stats)

    try:
        while True:
            # Get real network stats off the event loop
            current = await asyncio.to_thread(_get_real_network_stats)

            # Calculate deltas (traffic since last update)
            delta_in = max(0, current["bytes_in"] - prev_stats["bytes_in"])
            delta_out = max(0, current["bytes_out"] - prev_stats["bytes_out"])
            delta_packets = max(0, current["packets"] - prev_stats["packets"])
            prev_stats = current.copy()

            avg_packet_size = (delta_in + delta_out) / max(delta_packets, 1)

            # Send network_usage in the format the frontend expects
            usage_data = {
                "type": "network_usage",
                "data": {
                    "localhost": {
                        "id": "local-1",
                        "endpoint_id": "local-1",
                        "endpoint_name": "This Machine",
                        "bytes_in": delta_in,
                        "bytes_out": delta_out,
                        "packets": delta_packets,
                        "avg_packet_size": round(avg_packet_size, 2),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                },
            }
            await manager.send_personal_message(usage_data, websocket)

            await asyncio.sleep(3)
    except WebSocketDisconnect:
        manager.disconnect(websocket, "network")


async def websocket_alerts_endpoint(websocket: WebSocket):
    """WebSocket handler for real-time alerts.

    Streams new alerts from the database.  Each cycle fetches rows
    newer than the last seen timestamp so clients receive only fresh
    data instead of fabricated random alerts.
    """
    from app.database import SessionLocal
    from app.models.alert import Alert as AlertModel

    await manager.connect(websocket, "alerts")

    # High-water mark — only push alerts newer than this.
    last_seen_ts: datetime | None = None

    def _fetch_alerts(since_ts):
        """Sync DB work — run in thread pool."""
        db = SessionLocal()
        try:
            query = db.query(AlertModel).order_by(AlertModel.timestamp.desc())
            if since_ts is not None:
                query = query.filter(AlertModel.timestamp > since_ts)
            rows = query.limit(20).all()
            # Extract data while session is open
            result = []
            for row in reversed(rows):
                result.append({
                    "id": row.id,
                    "severity": row.severity,
                    "category": row.category,
                    "attack_type": row.attack_type,
                    "message": row.message,
                    "confidence": row.confidence,
                    "app_name": row.application.name if row.application else None,
                    "endpoint_id": row.endpoint_id,
                    "timestamp": row.timestamp.isoformat() if row.timestamp else datetime.now(timezone.utc).isoformat(),
                })
            newest_ts = rows[0].timestamp if rows else None
            return result, newest_ts
        finally:
            db.close()

    try:
        while True:
            alerts, newest_ts = await asyncio.to_thread(_fetch_alerts, last_seen_ts)

            for alert_data in alerts:
                await manager.send_personal_message(
                    {"type": "new_alert", "data": alert_data}, websocket
                )

            if newest_ts:
                last_seen_ts = newest_ts

            await asyncio.sleep(3)
    except WebSocketDisconnect:
        manager.disconnect(websocket, "alerts")


async def websocket_predictions_endpoint(websocket: WebSocket):
    """WebSocket handler for real-time ML predictions.

    Streams the latest predictions from the database to connected
    dashboard clients.  Each cycle fetches rows newer than the last
    seen timestamp so the client receives only fresh data.
    """
    from app.database import SessionLocal
    from app.models.ml_prediction import MLPrediction

    await manager.connect(websocket, "predictions")

    # Track the high-water mark so we only push new rows.
    last_seen_ts: datetime | None = None

    def _fetch_predictions(since_ts):
        """Sync DB work — run in thread pool."""
        db = SessionLocal()
        try:
            query = db.query(MLPrediction).order_by(MLPrediction.timestamp.desc())
            if since_ts is not None:
                query = query.filter(MLPrediction.timestamp > since_ts)
            rows = query.limit(20).all()
            result = []
            for row in reversed(rows):
                result.append({
                    "id": row.id,
                    "anomaly_score": row.anomaly_score,
                    "attack_type": row.attack_type or "Benign",
                    "confidence": row.confidence,
                    "action": row.action,
                    "app_name": row.app_name,
                    "src_ip": row.src_ip,
                    "dst_ip": row.dst_ip,
                    "context": row.context_json or {},
                    "timestamp": row.timestamp.isoformat() if row.timestamp else datetime.now(timezone.utc).isoformat(),
                })
            newest_ts = rows[0].timestamp if rows else None
            return result, newest_ts
        finally:
            db.close()

    try:
        while True:
            preds, newest_ts = await asyncio.to_thread(_fetch_predictions, last_seen_ts)

            for pred_data in preds:
                await manager.send_personal_message(
                    {"type": "prediction", "data": pred_data}, websocket
                )

            if newest_ts:
                last_seen_ts = newest_ts

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        manager.disconnect(websocket, "predictions")
