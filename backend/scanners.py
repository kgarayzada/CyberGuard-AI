"""Only trusted scanner configuration and explicit subprocess arguments are used."""
from pathlib import Path
import os, sys, json, subprocess, time, threading, urllib.request, re
from backend.engine import normalize, now
ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 90
OUTPUT_LIMIT = 12 * 1024 * 1024

def command(args, cwd, timeout=TIMEOUT):
    env = {**os.environ, 'SEMGREP_SEND_METRICS':'off', 'SEMGREP_ENABLE_VERSION_CHECK':'0', 'SEMGREP_SETTINGS_FILE':str(ROOT/'.tooling/semgrep-settings.yml'), 'OTEL_SDK_DISABLED':'true'}
    for k in ('SEMGREP_APP_TOKEN','GITLEAKS_CONFIG','GITLEAKS_CONFIG_TOML','PYTHONPATH'): env.pop(k,None)
    proc = subprocess.Popen([str(a) for a in args], cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    buffers = [bytearray(), bytearray()]; overflow = threading.Event()
    def kill_tree():
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if proc.poll() is None: proc.kill()
    def read(stream, buf):
        while data := stream.read(65536):
            if len(buf)+len(data) > OUTPUT_LIMIT: overflow.set(); kill_tree(); break
            buf.extend(data)
    threads = [threading.Thread(target=read,args=(stream,buf),daemon=True) for stream,buf in zip((proc.stdout,proc.stderr),buffers)]
    for t in threads:t.start()
    try: proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(); proc.wait(); raise TimeoutError('Scanner exceeded the assessment time limit.')
    finally:
        for t in threads:t.join(3)
        proc.stdout.close(); proc.stderr.close()
    if overflow.is_set(): raise ValueError('Scanner output limit exceeded.')
    return proc.returncode, buffers[0].decode('utf-8','replace'), buffers[1].decode('utf-8','replace')

def executable(name):
    if name == 'Semgrep': return ROOT/'.venv/Scripts/semgrep.exe'
    return ROOT/'.tooling/gitleaks/gitleaks.exe'

def availability():
    result=[]
    for name in ('Semgrep','Gitleaks'):
        exe=executable(name)
        version=None
        if exe.exists():
            try:
                code,out,_=command([exe,'--version' if name=='Semgrep' else 'version'],ROOT,45)
                if code==0: version=out.strip()[:100]
            except Exception: pass
        result.append(dict(scanner=name,available=version is not None,version=version))
    result.append(dict(scanner='OSV dependency analysis',available=True,version='OSV API v1',note='Optional internet lookup; only package names and versions are sent to api.osv.dev.'))
    return result

def safe_path(value, workspace):
    p=Path(value)
    if p.is_absolute():
        try: return p.resolve().relative_to(workspace.resolve()).as_posix()
        except ValueError: return None
    return p.as_posix() if '..' not in p.parts else None

def run_local(name, assessment, workspace):
    exe=executable(name)
    if not exe.exists(): return [],'Unavailable',f'{name} is currently unavailable.',None
    code,out,_=command([exe,'--version' if name=='Semgrep' else 'version'],ROOT,45)
    if code: return [],'Unavailable',f'{name} could not start.',None
    version=out.strip()[:100]
    if name=='Semgrep':
        args=[exe,'scan','--config',ROOT/'backend/rules/semgrep.yml','--json','--quiet','--metrics=off','--disable-version-check','--no-git-ignore','--no-rewrite-rule-ids','--timeout','15','--jobs','2',workspace]
        code,out,_=command(args,ROOT)
        if code not in (0,1): raise ValueError('Scanner returned an unsuccessful exit code.')
        payload=json.loads(out); findings=[]
        for r in payload.get('results',[]):
            extra=r.get('extra',{}); meta=extra.get('metadata',{})
            findings.append(normalize(assessment,name,r['check_id'],extra.get('message','Security pattern detected'),{'ERROR':'HIGH','WARNING':'MEDIUM','INFO':'LOW'}.get(extra.get('severity'),'UNKNOWN'),meta.get('category','Security Pattern'),safe_path(r['path'],workspace),r['start']['line'],r['end']['line'],confidence=meta.get('confidence'),cwe=meta.get('cwe')))
        return findings, 'Warning' if payload.get('errors') else 'Completed', f"{len(payload.get('paths',{}).get('scanned',[]))} files scanned using the bundled Python/JavaScript/TypeScript rule set." + (' Some files could not be analyzed.' if payload.get('errors') else ''),version
    report=workspace.parent/'gitleaks.json'
    args=[exe,'dir',workspace,'--config',ROOT/'backend/rules/gitleaks.toml','--report-format','json','--report-path',report,'--redact=100','--no-banner','--no-color','--exit-code','0','--timeout','75']
    code,_,_=command(args,ROOT)
    if code: raise ValueError('Scanner returned an unsuccessful exit code.')
    if report.stat().st_size>OUTPUT_LIMIT: raise ValueError('Scanner output limit exceeded.')
    findings=[]
    for r in json.loads(report.read_text(encoding='utf-8-sig')):
        findings.append(normalize(assessment,name,r['RuleID'],'Hardcoded credential pattern detected','HIGH','Credential Exposure',safe_path(r['File'],workspace),r.get('StartLine'),r.get('EndLine'),description='A secret-detection rule matched a credential-like value. Credential validity was not tested.',cwe='CWE-798'))
    report.unlink(missing_ok=True)
    return findings,'Completed','Default Gitleaks rules plus an API-credential assignment rule; source directory only.',version

def dependencies(workspace):
    packages=[]; skipped=0
    for p in workspace.rglob('*'):
        if not p.is_file(): continue
        if p.name=='package.json':
            doc=json.loads(p.read_text(encoding='utf-8-sig'))
            for group in ('dependencies','devDependencies'):
                for name,version in doc.get(group,{}).items():
                    if isinstance(version,str) and re.fullmatch(r'\d+\.\d+\.\d+(?:-[\w.]+)?',version): packages.append(('npm',name,version,p.relative_to(workspace).as_posix()))
                    else: skipped+=1
        elif p.name=='requirements.txt':
            for line in p.read_text(encoding='utf-8-sig').splitlines():
                if not line.strip() or line.lstrip().startswith('#'):continue
                m=re.fullmatch(r'\s*([\w.-]+)==([\w.+-]+)\s*',line)
                if m: packages.append(('PyPI',m[1],m[2],p.relative_to(workspace).as_posix()))
                else: skipped+=1
    if len(packages)>100: raise ValueError('Dependency analysis supports at most 100 exact package versions.')
    return sorted(set(packages)),skipped

def run_osv(assessment,workspace):
    if not assessment['dependency_lookup']: return [],'Skipped','Dependency lookup was not enabled.','OSV API v1'
    packages,skipped=dependencies(workspace)
    findings=[]; deadline=time.monotonic()+TIMEOUT
    # Fixed HTTPS endpoint only. Never use registry URLs or links from uploaded files.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('Dependency service redirect refused.')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for ecosystem,name,version,path in packages:
        token=None
        while True:
            if time.monotonic()>deadline: raise TimeoutError('Dependency analysis exceeded the assessment time limit.')
            body={'package':{'name':name,'ecosystem':ecosystem},'version':version}
            if token: body['page_token']=token
            request=urllib.request.Request('https://api.osv.dev/v1/query',json.dumps(body).encode(),{'Content-Type':'application/json'})
            with opener.open(request,timeout=min(12,max(1,deadline-time.monotonic()))) as response:
                if response.url!='https://api.osv.dev/v1/query': raise ValueError('Unexpected dependency-service redirect.')
                raw=response.read(OUTPUT_LIMIT+1)
                if len(raw)>OUTPUT_LIMIT: raise ValueError('Dependency response exceeds limit.')
                data=json.loads(raw)
            for v in data.get('vulns',[]):
                if v.get('withdrawn'):continue
                fixed=sorted({e['fixed'] for a in v.get('affected',[]) if a.get('package',{}).get('name')==name for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e})
                sev=v.get('database_specific',{}).get('severity','UNKNOWN')
                cves=[x for x in v.get('aliases',[]) if x.startswith('CVE-')]
                findings.append(normalize(assessment,'OSV dependency analysis',v['id'],v.get('summary') or v['id'],sev,'Vulnerable Dependency',path,description=v.get('details') or v.get('summary'),cve=', '.join(cves) or None,package=name,vulnerable_version=version,fixed_version=', '.join(fixed) or None,references=['https://osv.dev/vulnerability/'+v['id']]))
            token=data.get('next_page_token')
            if not token:break
    return findings,'Warning' if skipped else 'Completed',f'Checked {len(packages)} exact versions in package.json/requirements.txt; {skipped} unpinned or unsupported entries skipped. Other manifest formats are outside coverage.','OSV API v1'

