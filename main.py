from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import uvicorn
import os
import time

from database import (
    init_database, authenticate_user, create_user, get_user_by_username,
    get_or_create_ip, update_ip_tracking, increment_ip_count, block_ip, unblock_ip,
    get_all_tracked_ips, log_request, get_recent_requests, create_alert, 
    get_active_alerts, acknowledge_alert, get_threat_signatures,
    get_ip_request_patterns, get_high_risk_ips, get_statistics, get_settings, update_setting,
    get_db
)
from detection import threat_detector, ml_scorer
from auth import create_access_token, verify_token


ip_database = {}
MAX_REQUESTS = 10
WINDOW_SECONDS = 15


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  AEGIS SENTINEL KERNEL v3.0 INITIALIZED")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  Dashboard → http://127.0.0.1:8000/")
    print("  API Data  → http://127.0.0.1:8000/api/data")
    print("  Stats     → http://127.0.0.1:8000/api/stats")
    print("  Login     → http://127.0.0.1:8000/api/login")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    yield


app = FastAPI(
    title="Aegis Sentinel",
    description="Distributed Threat Mitigation System with ML-based Detection",
    version="3.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>index.html not found</h1>", status_code=404)


@app.post("/api/login")
async def login(request: Request):
    try:
        body = await request.json()
        username = body.get("username")
        password = body.get("password")
        
        if not username or not password:
            return JSONResponse(status_code=400, content={"error": "Username and password required"})
        
        user = authenticate_user(username, password)
        
        if user:
            token = create_access_token({
                "sub": username,
                "role": user.get("role", "operator"),
                "user_id": user.get("id")
            })
            return JSONResponse(content={
                "status": "success",
                "token": token,
                "user": {
                    "username": username,
                    "role": user.get("role", "operator")
                }
            })
        else:
            return JSONResponse(status_code=401, content={"error": "Invalid credentials"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/register")
async def register(request: Request):
    try:
        body = await request.json()
        username = body.get("username")
        password = body.get("password")
        
        if not username or not password:
            return JSONResponse(status_code=400, content={"error": "Username and password required"})
        
        if len(password) < 6:
            return JSONResponse(status_code=400, content={"error": "Password must be at least 6 characters"})
        
        if get_user_by_username(username):
            return JSONResponse(status_code=400, content={"error": "Username already exists"})
        
        if create_user(username, password):
            return JSONResponse(content={"status": "success", "message": "User created successfully"})
        else:
            return JSONResponse(status_code=500, content={"error": "Failed to create user"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/data")
async def security_check(request: Request):
    start_time = time.time()
    client_ip = request.client.host
    now = datetime.now()

    user_agent = request.headers.get("user-agent", "Unknown")
    accept_lang = request.headers.get("accept-language", "N/A")
    referer = request.headers.get("referer", "Direct")
    x_forwarded = request.headers.get("x-forwarded-for", None)
    real_ip = x_forwarded.split(",")[0].strip() if x_forwarded else client_ip

    headers_dict = dict(request.headers)

    if real_ip not in ip_database:
        ip_database[real_ip] = {
            "count": 1,
            "window_start": now,
            "blocked": False,
            "blocked_at": None,
            "total_requests": 1,
            "first_seen": now,
            "user_agents": [user_agent],
            "threat_score": 0.0,
            "risk_level": "low",
            "last_analysis": None
        }
    else:
        entry = ip_database[real_ip]
        entry["total_requests"] += 1

        if now - entry["window_start"] > timedelta(seconds=WINDOW_SECONDS):
            entry["count"] = 1
            entry["window_start"] = now
            entry["blocked"] = False
            entry["blocked_at"] = None
        else:
            entry["count"] += 1

        if user_agent not in entry["user_agents"]:
            entry["user_agents"].append(user_agent)
            if len(entry["user_agents"]) > 5:
                entry["user_agents"].pop(0)

        time_since_first = (now - entry["first_seen"]).total_seconds()
        patterns = get_ip_request_patterns(real_ip, WINDOW_SECONDS)

        analysis = threat_detector.analyze_request(
            ip_address=real_ip,
            headers=headers_dict,
            user_agent=user_agent,
            path=str(request.url.path),
            request_count=entry["count"],
            window_seconds=WINDOW_SECONDS,
            time_since_first_request=time_since_first,
            unique_paths=patterns.get("unique_paths", 1),
            unique_agents=patterns.get("unique_agents", 1),
            recent_requests=patterns.get("total_requests", 0)
        )

        entry["threat_score"] = analysis.threat_score
        entry["risk_level"] = analysis.risk_level
        entry["last_analysis"] = analysis

        if analysis.severity == "critical" and not entry["blocked"]:
            entry["blocked"] = True
            entry["blocked_at"] = now
            create_alert(
                ip_address=real_ip,
                severity="critical",
                message=f"Critical threat detected: {'; '.join(analysis.detected_patterns)}",
                threat_score=analysis.threat_score
            )
        elif entry["count"] > MAX_REQUESTS and not entry["blocked"]:
            entry["blocked"] = True
            entry["blocked_at"] = now
            create_alert(
                ip_address=real_ip,
                severity="high",
                message=f"Rate limit exceeded: {entry['count']} requests in {WINDOW_SECONDS}s",
                threat_score=0.8
            )

        update_ip_tracking(
            real_ip,
            blocked=entry["blocked"],
            threat_score=analysis.threat_score,
            risk_level=analysis.risk_level
        )

    entry = ip_database[real_ip]
    is_blocked = entry["blocked"]

    response_time_ms = (time.time() - start_time) * 1000

    log_request(
        ip_address=real_ip,
        status="danger" if is_blocked else "success",
        count=entry["count"],
        user_agent=user_agent,
        threat_score=entry["threat_score"],
        headers_count=len(headers_dict),
        response_time_ms=response_time_ms
    )

    analysis_data = entry.get("last_analysis")
    
    payload = {
        "status": "danger" if is_blocked else "success",
        "message": "DDoS SIGNATURE DETECTED - IP QUARANTINED" if is_blocked else "Request Processed Successfully",
        "ip": real_ip,
        "count": entry["count"],
        "total_requests": entry["total_requests"],
        "window_seconds": WINDOW_SECONDS,
        "max_requests": MAX_REQUESTS,
        "window_start": entry["window_start"].isoformat(),
        "first_seen": entry["first_seen"].isoformat(),
        "blocked": is_blocked,
        "blocked_at": entry.get("blocked_at").isoformat() if entry.get("blocked_at") else None,
        "user_agent": user_agent,
        "accept_language": accept_lang,
        "referer": referer,
        "method": request.method,
        "path": str(request.url.path),
        "timestamp": now.isoformat(),
        "headers_count": len(headers_dict),
        "threat_score": entry["threat_score"],
        "risk_level": entry["risk_level"],
        "detected_patterns": analysis_data.detected_patterns if analysis_data else [],
        "ml_analysis": {
            "confidence": analysis_data.confidence if analysis_data else 0,
            "recommendations": analysis_data.recommendations if analysis_data else []
        } if analysis_data else None,
        "response_time_ms": round(response_time_ms, 2)
    }

    return JSONResponse(content=payload)


@app.get("/api/stats")
async def get_stats(request: Request):
    stats = get_statistics()
    
    top_ips = get_all_tracked_ips()[:10]
    for ip in top_ips:
        for key in ["window_start", "first_seen", "last_seen", "blocked_at"]:
            if key in ip and ip[key] and hasattr(ip[key], "isoformat"):
                ip[key] = ip[key].isoformat()
    
    recent_requests = get_recent_requests(50)
    for req in recent_requests:
        if hasattr(req.get("timestamp"), "isoformat"):
            req["timestamp"] = req["timestamp"].isoformat()
    
    alerts = get_active_alerts(acknowledged=False)
    for alert in alerts:
        if hasattr(alert.get("created_at"), "isoformat"):
            alert["created_at"] = alert["created_at"].isoformat()
        if hasattr(alert.get("acknowledged_at"), "isoformat"):
            alert["acknowledged_at"] = alert["acknowledged_at"].isoformat()
    
    high_risk = get_high_risk_ips(threshold=0.5)
    
    return JSONResponse(content={
        **stats,
        "top_ips": top_ips,
        "recent_requests": recent_requests,
        "active_alerts": alerts,
        "high_risk_ips": high_risk,
        "server_time": datetime.now().isoformat()
    })


@app.get("/api/alerts")
async def get_alerts(request: Request, acknowledged: bool = False):
    alerts = get_active_alerts(acknowledged=acknowledged)
    for alert in alerts:
        if hasattr(alert.get("created_at"), "isoformat"):
            alert["created_at"] = alert["created_at"].isoformat()
    return JSONResponse(content={"alerts": alerts})


@app.post("/api/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: int, request: Request):
    try:
        body = await request.json()
        username = body.get("username", "unknown")
    except:
        username = "unknown"
    
    if acknowledge_alert(alert_id, username):
        return JSONResponse(content={"status": "success"})
    return JSONResponse(status_code=404, content={"error": "Alert not found"})


@app.get("/api/threat-analysis/{ip}")
async def analyze_ip(ip: str, request: Request):
    patterns = get_ip_request_patterns(ip, 300)
    headers_dict = dict(request.headers)
    
    analysis = threat_detector.analyze_request(
        ip_address=ip,
        headers=headers_dict,
        user_agent="Analysis Request",
        path="/",
        request_count=patterns.get("total_requests", 0),
        window_seconds=WINDOW_SECONDS,
        time_since_first_request=300,
        unique_paths=patterns.get("unique_paths", 1),
        unique_agents=patterns.get("unique_agents", 1),
        recent_requests=patterns.get("total_requests", 0)
    )
    
    ml_result = ml_scorer.calculate_threat_score(
        request_count=patterns.get("total_requests", 0),
        time_window=300,
        unique_paths=patterns.get("unique_paths", 1),
        unique_headers=len(headers_dict),
        request_intervals=[]
    )
    
    return JSONResponse(content={
        "ip": ip,
        "patterns": patterns,
        "threat_analysis": {
            "threat_score": analysis.threat_score,
            "risk_level": analysis.risk_level,
            "severity": analysis.severity,
            "detected_patterns": analysis.detected_patterns,
            "recommendations": analysis.recommendations,
            "confidence": analysis.confidence
        },
        "ml_prediction": ml_result,
        "threat_category": ml_scorer.predict_threat_category(ml_result["features"]),
        "analyzed_at": datetime.now().isoformat()
    })


@app.get("/api/ml-training-data")
async def get_ml_training_data(request: Request):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address, COUNT(*) as total_requests, 
                   AVG(threat_score) as avg_threat,
                   MAX(threat_score) as max_threat,
                   COUNT(DISTINCT user_agent) as unique_agents,
                   SUM(CASE WHEN status = 'danger' THEN 1 ELSE 0 END) as blocked_count
            FROM request_log
            GROUP BY ip_address
            HAVING total_requests > 5
        """)
        features = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT threat_score, risk_level FROM ip_tracking 
            WHERE threat_score > 0
        """)
        labeled = [dict(row) for row in cursor.fetchall()]
        
        return JSONResponse(content={
            "features": features,
            "labeled_data": labeled,
            "model_version": "1.0.0",
            "training_samples": len(features)
        })


@app.delete("/api/unblock/{ip}")
async def unblock_ip_route(ip: str):
    if ip in ip_database:
        ip_database[ip]["blocked"] = False
        ip_database[ip]["count"] = 0
        ip_database[ip]["blocked_at"] = None
        ip_database[ip]["threat_score"] = 0.0
        ip_database[ip]["risk_level"] = "low"
    
    unblock_ip(ip)
    return JSONResponse(content={"status": "ok", "message": f"{ip} has been unblocked"})


@app.delete("/api/reset")
async def reset_all():
    ip_database.clear()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM request_log")
        cursor.execute("DELETE FROM alerts")
        cursor.execute("UPDATE ip_tracking SET blocked = 0, count = 0, threat_score = 0, risk_level = 'low'")
    return JSONResponse(content={"status": "ok", "message": "All tracking data cleared"})


@app.get("/api/settings")
async def get_config():
    return JSONResponse(content=get_settings())


@app.post("/api/settings")
async def update_config(request: Request):
    try:
        body = await request.json()
        for key, value in body.items():
            update_setting(key, str(value))
        
        global MAX_REQUESTS, WINDOW_SECONDS
        MAX_REQUESTS = int(body.get("max_requests", MAX_REQUESTS))
        WINDOW_SECONDS = int(body.get("window_seconds", WINDOW_SECONDS))
        
        return JSONResponse(content={"status": "success"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
