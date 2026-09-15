"""Real integration QA. Run with the app started; reset afterward."""
from pathlib import Path
import io,json,time,zipfile,urllib.request,urllib.error,sqlite3
ROOT=Path(__file__).resolve().parents[1]
BASE='http://127.0.0.1:5173/api'
def request(path,method='GET',body=None,headers=None):
    req=urllib.request.Request(BASE+path,body,headers or {},method=method)
    with urllib.request.urlopen(req,timeout=120) as r:return json.load(r)
def zipped(files):
    b=io.BytesIO()
    with zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED) as z:
        for n,text in files.items():z.writestr(n,text)
    return b.getvalue()
def upload(content,filename='source.zip',name='QA',lookup=False):
    boundary='CyberGuardBoundaryQA'
    fields={'project_name':name,'authorized':'true','environment':'Production','criticality':'High','dependency_lookup':str(lookup).lower()}
    body=b''
    for k,v in fields.items():body+=f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    body+=f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: application/zip\r\n\r\n'.encode()+content+f'\r\n--{boundary}--\r\n'.encode()
    return request('/assessments/upload','POST',body,{'Content-Type':'multipart/form-data; boundary='+boundary})
def scan(content,name,lookup=False):
    a=upload(content,name=name,lookup=lookup);request('/assessments/'+a['id']+'/start','POST')
    deadline=time.monotonic()+360
    while time.monotonic()<deadline:
        a=request('/assessments/'+a['id'])
        if a['status'] not in ('Uploaded','Scanning'):break
        time.sleep(1)
    assert a['status'].startswith('Completed'),a
    print(name,a['status'],len(a['findings']),[(r['scanner'],r['status']) for r in a['scanner_runs']],flush=True)
    assert not (ROOT/'data/workspaces'/a['id']).exists()
    return a
if __name__=='__main__':
    checks=[]
    initial=request('/dashboard');assert initial['latest'] is None and not request('/findings');checks.append('Clean database: zero findings and assessments')
    for label,content,name in [('non-zip',b'not zip','x.txt'),('corrupt',b'PKbroken','x.zip'),('traversal',zipped({'../escape.txt':'bad'}),'x.zip'),('empty',zipped({}),'x.zip'),('absolute',zipped({'/absolute.txt':'bad'}),'x.zip'),('device',zipped({'CON.txt':'bad'}),'x.zip'),('bomb',zipped({'large.txt':'0'*(5*1024*1024)}),'x.zip'),('oversized',b'x'*(21*1024*1024),'x.zip')]:
        try:upload(content,name)
        except urllib.error.HTTPError as e:assert e.code in (413,422),(label,e.code)
        else:raise AssertionError(label+' accepted')
        checks.append('Rejected '+label)
    assert not list((ROOT/'data/workspaces').iterdir())
    a=scan((ROOT/'demo/cyberguard-vulnerable-demo.zip').read_bytes(),'CyberGuard Vulnerable Demo',True)
    assert any(f['scanner']=='Semgrep' for f in a['findings']),a['scanner_runs']
    assert any(f['scanner']=='Gitleaks' for f in a['findings']),a['scanner_runs']
    assert 'CG_DEMO_FAKE_API_KEY_NOT_REAL_2026' not in json.dumps(a)
    assert any(f['scanner_rule_id']=='python-sql-concatenation' for f in a['findings'])
    checks.append('Real demo upload, scanner-derived findings, redacted persistence and workspace cleanup')
    report=request('/reports/'+a['id']);assert len(report['findings'])==len(a['findings'])
    for f in a['findings']:assert request('/findings/'+f['id'])['fingerprint']==f['fingerprint']
    checks.append('Finding detail and assessment report APIs')
    clean=scan(zipped({'hello.py':'def greet():\n    return "hello"\n'}),'Clean source')
    assert not clean['findings'];checks.append('Clean source returns zero findings')
    with zipfile.ZipFile(ROOT/'demo/cyberguard-vulnerable-demo.zip') as z:files={n:z.read(n) for n in z.namelist()}
    files['example.py']=files['example.py'].decode('utf-8-sig').replace('database.execute("SELECT name FROM customers WHERE name = \'" + supplied_name)','database.execute("SELECT name FROM customers WHERE name = ?", (supplied_name,))').encode()
    changed=scan(zipped(files),'SQL fixed source')
    assert not any(f['scanner_rule_id']=='python-sql-concatenation' for f in changed['findings'])
    assert changed['findings'];checks.append('Parameterized SQL removes associated real Semgrep finding')
    with sqlite3.connect(ROOT/'data/cyberguard.db') as c:assert c.execute('SELECT count(*) FROM findings WHERE assessment_id=?',(a['id'],)).fetchone()[0]==len(a['findings'])
    checks.append('SQLite persistence matches normalized results')
    (ROOT/'data/qa-results.json').write_text(json.dumps({'demo_id':a['id'],'demo_count':len(a['findings']),'scanner_runs':a['scanner_runs'],'checks':checks},indent=2))
    print('PASS',json.dumps(checks),flush=True)
