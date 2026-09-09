from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from datetime import datetime, timezone
import argparse
import asyncio
import json
import sqlite3
import time
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Literal
from backend.engine import ASSET, FINDINGS, PATHS, STAGES, DISCLAIMER, QUESTIONS, analysis, analyst

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "cyberguard.db"

@contextmanager
def database():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def now(): return datetime.now(timezone.utc).isoformat()
def scan_dict(row):
    s = dict(row)
    s["findings"] = json.loads(s["findings"])
    return s

def initialize():
    DB.parent.mkdir(exist_ok=True)
    with database() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, date TEXT NOT NULL, status TEXT NOT NULL, score INTEGER, duration INTEGER NOT NULL, progress INTEGER NOT NULL, stage TEXT NOT NULL, started REAL NOT NULL, findings TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, created TEXT NOT NULL, payload TEXT NOT NULL);
        """)
        if c.execute("SELECT count(*) FROM assets").fetchone()[0]: return
        c.execute("INSERT INTO assets VALUES (?,?)", (ASSET["id"], json.dumps(ASSET)))
        for f in FINDINGS: c.execute("INSERT INTO findings VALUES (?,?)", (f["id"], json.dumps(f)))
        for day, score, duration in [("2026-08-20",43,193),("2026-08-27",47,181),("2026-09-03",51,172),("2026-09-10",58,167)]:
            snapshot = json.loads(json.dumps(FINDINGS))
            if score < 58: snapshot[-1]["status"] = "OPEN"
            for f in snapshot: f["last_detected"] = day + "T09:00:00Z"
            c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?)", ("CG-"+day.replace("-", "",1).replace("-", "")[:4]+"-"+day[5:].replace("-", "")+"-001",day+"T09:00:00Z","COMPLETED",score,duration,100,"Complete",0,json.dumps(snapshot)))

def advance_scans():
    # Persisted timestamps drive a short simulation. No worker queue, no target requests.
    with database() as c:
        for row in c.execute("SELECT * FROM scans WHERE status NOT IN ('COMPLETED','FAILED')").fetchall():
            elapsed = max(0, time.time() - row["started"])
            progress = min(100, int(elapsed / 6.5 * 100))
            stage = STAGES[min(9, progress // 10)] if progress < 100 else "Complete"
            status = "INITIALIZING" if progress < 10 else "RUNNING" if progress < 60 else "ANALYZING" if progress < 100 else "COMPLETED"
            findings = row["findings"]
            if progress == 100:
                snapshot = []
                for current in c.execute("SELECT payload FROM findings ORDER BY id").fetchall():
                    f = json.loads(current[0])
                    f["last_detected"] = row["date"]
                    c.execute("UPDATE findings SET payload=? WHERE id=?",(json.dumps(f), f["id"]))
                    snapshot.append(f)
                findings = json.dumps(snapshot)
            c.execute("UPDATE scans SET progress=?,stage=?,status=?,score=?,duration=?,findings=? WHERE id=?",(progress,stage,status,58 if progress==100 else None,7 if progress==100 else int(elapsed),findings,row["id"]))

async def ticker():
    while True:
        await asyncio.sleep(.2)
        await asyncio.to_thread(advance_scans)

@asynccontextmanager
async def lifespan(app):
    initialize()
    advance_scans()
    task = asyncio.create_task(ticker())
    yield
    task.cancel()
    try: await task
    except asyncio.CancelledError: pass

app = FastAPI(title="CyberGuard AI Local API", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173","http://localhost:5173"], allow_methods=["GET","POST","PATCH"], allow_headers=["Content-Type"])

@app.exception_handler(Exception)
async def graceful_error(request, exc):
    return JSONResponse(status_code=500, content={"detail":"The local assessment service could not complete this operation. Please retry."})

@app.get("/api/health")
def health(): return {"service":"cyberguard-ai", "status":"ok", "workspace":str(ROOT)}

def state():
    advance_scans()
    with database() as c:
        asset = json.loads(c.execute("SELECT payload FROM assets").fetchone()[0])
        findings = [json.loads(r[0]) for r in c.execute("SELECT payload FROM findings ORDER BY id")]
        scans = [scan_dict(r) for r in c.execute("SELECT * FROM scans ORDER BY started DESC,date DESC")]
    active = [f for f in findings if f["status"] == "OPEN"]
    completed = [s for s in scans if s["status"] == "COMPLETED"]
    paths = [p for p in PATHS if all(any(f["id"]==fid for f in active) for fid in p["findings"])]
    return {"asset":asset,"findings":findings,"scans":scans,"paths":paths,"questions":QUESTIONS,"disclaimer":DISCLAIMER,"summary":{"score": completed[0]["score"], "previous":completed[1]["score"] if len(completed)>1 else 51,"open":len(active),"resolved":sum(f["status"]=="RESOLVED" for f in findings),"severity":{s:sum(f["severity"]==s for f in active) for s in ["CRITICAL","HIGH","MEDIUM","LOW"]}}}

@app.get("/api/state")
def get_state(): return state()

@app.post("/api/scans", status_code=201)
def start_scan():
    advance_scans()
    with database() as c:
        c.execute("BEGIN IMMEDIATE")
        active = c.execute("SELECT * FROM scans WHERE status NOT IN ('COMPLETED','FAILED') LIMIT 1").fetchone()
        if active: return scan_dict(active)
        stamp = now()
        sid = "CG-"+datetime.now(timezone.utc).strftime("%Y-%m%d")+"-"+uuid.uuid4().hex[:6].upper()
        c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?)",(sid,stamp,"QUEUED",None,0,0,STAGES[0],time.time(),"[]"))
        return scan_dict(c.execute("SELECT * FROM scans WHERE id=?",(sid,)).fetchone())

@app.get("/api/scans/{scan_id}")
def scan(scan_id:str):
    advance_scans()
    with database() as c: row = c.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
    if not row: raise HTTPException(404,"Assessment not found.")
    return scan_dict(row)

@app.get("/api/findings/{finding_id}")
def finding(finding_id:str):
    with database() as c: row = c.execute("SELECT payload FROM findings WHERE id=?",(finding_id,)).fetchone()
    if not row: raise HTTPException(404,"Finding not found.")
    f = json.loads(row[0])
    return {**f,"analysis":analysis(f)}

class Disposition(BaseModel):
    status: Literal["OPEN","RESOLVED","ACCEPTED","FALSE POSITIVE"]

@app.patch("/api/findings/{finding_id}")
def update_status(finding_id:str, body:Disposition):
    with database() as c:
        row = c.execute("SELECT payload FROM findings WHERE id=?",(finding_id,)).fetchone()
        if not row: raise HTTPException(404,"Finding not found.")
        f = json.loads(row[0]); f["status"] = body.status
        c.execute("UPDATE findings SET payload=? WHERE id=?",(json.dumps(f),finding_id))
    return {**f,"analysis":analysis(f)}

class Question(BaseModel):
    question:str

@app.post("/api/analyst")
def ask(body:Question):
    if body.question not in QUESTIONS: raise HTTPException(422,"Choose one of the supported analysis questions.")
    s = state()
    return {**analyst(body.question,s["findings"],s["summary"]["score"],s["paths"]),"method":"Deterministic local rules · No external AI", "generated":now()}

def report_payload():
    s = state()
    s["assessment"] = next(scan for scan in s["scans"] if scan["status"]=="COMPLETED")
    s["analysis"] = analyst(QUESTIONS[5],s["findings"],s["summary"]["score"],s["paths"])
    s["priorities"] = analyst(QUESTIONS[4],s["findings"],s["summary"]["score"],s["paths"])
    s["generated"] = now()
    return s

@app.get("/api/reports/current")
def report_current(): return report_payload()

@app.post("/api/reports",status_code=201)
def generate_report():
    payload = report_payload()
    payload["id"] = "CG-RPT-"+uuid.uuid4().hex[:8].upper()
    with database() as c: c.execute("INSERT INTO reports VALUES (?,?,?)",(payload["id"],payload["generated"],json.dumps(payload)))
    return payload

@app.get("/api/reports")
def list_reports():
    with database() as c: return [dict(r) for r in c.execute("SELECT id,created FROM reports ORDER BY created DESC")]

@app.get("/api/reports/{report_id}")
def saved_report(report_id:str):
    with database() as c: row = c.execute("SELECT payload FROM reports WHERE id=?",(report_id,)).fetchone()
    if not row: raise HTTPException(404,"Report not found.")
    return json.loads(row[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--reset",action="store_true"); args=parser.parse_args()
    if args.reset:
        # Reset only our known application tables; preserve source and dependencies.
        initialize()
        with database() as c:
            for table in ("reports","scans","findings","assets"): c.execute("DELETE FROM " + table)
    initialize()
    print("CyberGuard demo database ready.")
