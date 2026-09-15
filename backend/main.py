from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
import argparse, json, sqlite3, uuid, shutil, logging, threading
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Literal
from backend.archive import extract, ArchiveError, MAX_UPLOAD
from backend.engine import now, security_score, SEVERITIES
from backend.scanners import availability, run_local, run_osv

ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'data/cyberguard.db'
WORK=ROOT/'data/workspaces'
POOL=ThreadPoolExecutor(max_workers=1)
UPLOAD_LOCK=threading.Lock()
log=logging.getLogger('cyberguard')

@contextmanager
def database():
    c=sqlite3.connect(DB,timeout=20); c.row_factory=sqlite3.Row
    try: yield c; c.commit()
    except Exception: c.rollback(); raise
    finally:c.close()

def initialize():
    DB.parent.mkdir(exist_ok=True); WORK.mkdir(exist_ok=True)
    with database() as c:
        # Explicit one-time migration removes the obsolete presentation schema/data.
        if c.execute("SELECT name FROM sqlite_master WHERE name='assets'").fetchone():
            c.executescript('DROP TABLE IF EXISTS assets; DROP TABLE IF EXISTS findings; DROP TABLE IF EXISTS scans; DROP TABLE IF EXISTS reports;')
        c.executescript('''CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,assessment_id TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS finding_assessment ON findings(assessment_id);
        CREATE TABLE IF NOT EXISTS scanner_runs(assessment_id TEXT NOT NULL,scanner TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(assessment_id,scanner));''')

def save(a):
    with database() as c:c.execute('INSERT OR REPLACE INTO assessments VALUES (?,?)',(a['id'],json.dumps(a)))
def get(aid):
    with database() as c:r=c.execute('SELECT payload FROM assessments WHERE id=?',(aid,)).fetchone()
    if not r:raise HTTPException(404,'Assessment not found.')
    return json.loads(r[0])
def all_assessments():
    with database() as c: rows=c.execute('SELECT payload FROM assessments ORDER BY rowid DESC').fetchall()
    return [json.loads(r[0]) for r in rows]
def findings_for(aid):
    with database() as c:rows=c.execute('SELECT payload FROM findings WHERE assessment_id=?',(aid,)).fetchall()
    return sorted([json.loads(r[0]) for r in rows],key=lambda f:(-f['contextual_risk_score'],f['id']))
def cleanup(aid):
    target=(WORK/aid).resolve()
    if target.parent!=WORK.resolve():raise ValueError('Invalid workspace')
    if target.exists():shutil.rmtree(target)

def worker(aid):
    a=get(aid); results=[]
    try:
        for name in ('Semgrep','Gitleaks','OSV dependency analysis'):
            a['stage']='Running '+name; save(a)
            run=dict(scanner=name,status='Running',started_at=now(),ended_at=None,version=None,message=None)
            a['scanner_runs'].append(run);save(a)
            try:
                items,status,message,version=run_osv(a,WORK/aid/'source') if name.startswith('OSV') else run_local(name,a,WORK/aid/'source')
                results.extend(items);run.update(status=status,message=message,version=version,finding_count=len(items))
            except TimeoutError:
                run.update(status='Timeout',message=f'{name} exceeded the assessment time limit.',finding_count=0)
            except Exception as exc:
                # Never log scanner stdout/stderr, uploaded text or exception bodies (may contain credentials).
                log.error('Scanner failure assessment=%s scanner=%s type=%s',aid,name,type(exc).__name__)
                run.update(status='Failed',message=f'{name} could not complete. No results were fabricated for this scanner.',finding_count=0)
            run['ended_at']=now()
            with database() as c:c.execute('INSERT OR REPLACE INTO scanner_runs VALUES (?,?,?)',(aid,name,json.dumps(run)))
            save(a)
        a['stage']='Normalizing findings and calculating risk';save(a)
        unique={f['fingerprint']:f for f in results};results=list(unique.values())
        usable=any(r['status'] in ('Completed','Warning') for r in a['scanner_runs'])
        a.update(total_findings=len(results),severity_counts={s:sum(f['severity']==s for f in results) for s in SEVERITIES},security_score=security_score(results) if usable else None)
        a['status']=('Completed' if all(r['status']=='Completed' for r in a['scanner_runs']) else 'Completed with warnings') if usable else 'Failed'
        a['message']='Results reflect completed scanner coverage only. A high score is not proof of security.' if usable else 'Assessment could not be completed. No findings were fabricated.'
        with database() as c:
            for f in results:c.execute('INSERT OR REPLACE INTO findings VALUES (?,?,?)',(f['id'],aid,json.dumps(f)))
    except Exception as exc:
        log.error('Assessment failure id=%s type=%s',aid,type(exc).__name__)
        a.update(status='Failed',message='Assessment could not be completed. No findings were fabricated.')
    finally:
        try:cleanup(aid)
        except OSError:log.error('Workspace cleanup failed for %s',aid);a['message']='Temporary source cleanup failed; use reset to remove retained files.'
        a['ended_at']=now();a['stage']=a['status'];save(a)

@asynccontextmanager
async def lifespan(app):
    initialize()
    for a in all_assessments():
        if a['status'] in ('Scanning','Uploaded'):
            a.update(status='Failed',stage='Interrupted',ended_at=now(),message='Interrupted by application restart. Upload the project again.')
            for run in a['scanner_runs']:
                if run['status']=='Running':
                    run.update(status='Interrupted',ended_at=now(),message='Application stopped before this scanner completed.')
                    with database() as c:c.execute('INSERT OR REPLACE INTO scanner_runs VALUES (?,?,?)',(a['id'],run['scanner'],json.dumps(run)))
            save(a);cleanup(a['id'])
    yield
    POOL.shutdown(wait=True)

app=FastAPI(title='CyberGuard Static Assessment',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=['http://127.0.0.1:5173','http://localhost:5173'],allow_methods=['GET','POST','PATCH'],allow_headers=['Content-Type'])

# Bound the entire request before multipart parsing/spooling, including chunked uploads.
class RequestGuard:
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        headers=dict(scope['headers']);origin=headers.get(b'origin',b'').decode()
        if scope['method'] not in ('GET','HEAD','OPTIONS') and origin and origin not in ('http://127.0.0.1:5173','http://localhost:5173','http://127.0.0.1:8000'):
            return await JSONResponse({'detail':'Origin is not allowed.'},403)(scope,receive,send)
        if scope['method'] in ('POST','PATCH'):
            chunks=[];size=0;limit=MAX_UPLOAD+65536 if scope['path']=='/api/assessments/upload' else 65536
            while True:
                msg=await receive()
                if msg['type']=='http.disconnect':return
                size+=len(msg.get('body',b''))
                if size>limit:return await JSONResponse({'detail':'Upload exceeds the 20 MiB request limit.'},413)(scope,receive,send)
                chunks.append(msg)
                if not msg.get('more_body'):break
            async def replay():
                return chunks.pop(0) if chunks else await receive()
            return await self.app(scope,replay,send)
        await self.app(scope,receive,send)
app.add_middleware(RequestGuard)

@app.exception_handler(Exception)
async def failure(request,exc):
    log.error('API failure type=%s',type(exc).__name__)
    return JSONResponse({'detail':'The local assessment service could not complete this operation.'},500)
@app.get('/api/health')
def health():return {'service':'cyberguard-ai','status':'ok','workspace':str(ROOT)}
@app.get('/api/scanners')
def scanners():return availability()
@app.post('/api/assessments/upload',status_code=201)
def upload(file:UploadFile=File(...),project_name:str=Form(''),environment:Literal['','Development','Testing','Staging','Production']=Form(''),criticality:Literal['','Low','Medium','High','Critical']=Form(''),dependency_lookup:bool=Form(False),authorized:bool=Form(False)):
    if not authorized:raise HTTPException(422,'Confirm you own or are authorized to assess this source code.')
    if len(project_name)>120:raise HTTPException(422,'Project name must be 120 characters or fewer.')
    if not file.filename or not file.filename.lower().endswith('.zip'):raise HTTPException(422,'Only .zip source archives are supported.')
    if not UPLOAD_LOCK.acquire(blocking=False):raise HTTPException(409,'Another upload is being prepared. Please retry.')
    aid=uuid.uuid4().hex
    try:
        if any(a['status'] in ('Uploaded','Scanning') for a in all_assessments()):raise HTTPException(409,'Finish the active assessment before uploading another project.')
        container=WORK/aid;container.mkdir();archive=container/'upload.zip';size=0
        with archive.open('xb') as out:
            while chunk:=file.file.read(65536):
                size+=len(chunk)
                if size>MAX_UPLOAD:raise HTTPException(413,'Upload exceeds the 20 MiB limit.')
                out.write(chunk)
        stats=extract(archive,container/'source');archive.unlink()
        filename=file.filename.replace('\\','/').split('/')[-1]
        filename=''.join(c for c in filename if c.isprintable())[:160]
        a=dict(id=aid,project_name=project_name.strip() or filename,uploaded_filename=filename,upload_size=size,uploaded_at=now(),started_at=None,ended_at=None,environment=environment or None,criticality=criticality or None,dependency_lookup=dependency_lookup,status='Uploaded',stage='Archive validated and safely extracted',archive=stats,scanner_runs=[],total_findings=0,severity_counts={},security_score=None,message=None)
        save(a);return a
    except ArchiveError as exc:cleanup(aid);raise HTTPException(422,str(exc))
    except Exception:cleanup(aid);raise
    finally:UPLOAD_LOCK.release();file.file.close()
@app.post('/api/assessments/{aid}/start')
def start(aid:str):
    with UPLOAD_LOCK:
        a=get(aid)
        if a['status']!='Uploaded':raise HTTPException(409,'Only an uploaded assessment can be started.')
        a.update(status='Scanning',stage='Preparing scanners',started_at=now());save(a);POOL.submit(worker,aid)
    return a
@app.get('/api/assessments')
def assessments():return all_assessments()
@app.get('/api/assessments/{aid}')
@app.get('/api/assessments/{aid}/status')
def assessment(aid:str):return {**get(aid),'findings':findings_for(aid)}
@app.get('/api/findings')
def findings(assessment_id:str|None=None):
    if assessment_id:return findings_for(assessment_id)
    with database() as c:return [json.loads(r[0]) for r in c.execute('SELECT payload FROM findings')]
@app.get('/api/findings/{fid}')
def finding(fid:str):
    with database() as c:r=c.execute('SELECT payload FROM findings WHERE id=?',(fid,)).fetchone()
    if not r:raise HTTPException(404,'Finding not found.')
    return json.loads(r[0])
class Disposition(BaseModel):status:Literal['OPEN','RESOLVED','ACCEPTED','FALSE POSITIVE']
@app.patch('/api/findings/{fid}')
def disposition(fid:str,body:Disposition):
    f=finding(fid);f['status']=body.status
    with database() as c:c.execute('UPDATE findings SET payload=? WHERE id=?',(json.dumps(f),fid))
    return f
@app.get('/api/dashboard')
def dashboard():
    history=all_assessments();completed=[a for a in history if a['status'].startswith('Completed')];latest=completed[0] if completed else None
    return dict(assessments=history,latest=latest,findings=findings_for(latest['id']) if latest else [],trend=[{'id':a['id'],'project_name':a['project_name'],'date':a['ended_at'],'score':a['security_score']} for a in reversed(completed)])
@app.get('/api/reports/{aid}')
def report(aid:str):
    a=get(aid)
    if not a['status'].startswith('Completed'):raise HTTPException(409,'A report requires a completed assessment.')
    fs=findings_for(aid)
    return dict(assessment=a,findings=fs,generated_at=now(),executive_summary=f"Static assessment identified {len(fs)} findings within the completed scanner coverage. Prioritize the highest contextual risk findings and validate fixes by rescanning. No exploitation or credential validation was performed.")

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--reset',action='store_true');args=parser.parse_args()
    if args.reset:
        for suffix in ('','-wal','-shm','-journal'):Path(str(DB)+suffix).unlink(missing_ok=True)
        if WORK.exists():
            for p in WORK.iterdir():
                if p.is_dir():cleanup(p.name)
    initialize();print('CyberGuard database ready: no seeded data.')
