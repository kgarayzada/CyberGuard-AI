"""Run after stopping/restarting an existing QA session. Restore scanners in finally."""
import json,time
from pathlib import Path
import runpy
helpers=runpy.run_path(str(Path(__file__).with_name('verify-api.py')))
request,scan,upload,ROOT=(helpers[k] for k in ('request','scan','upload','ROOT'))
saved=json.loads((ROOT/'data/qa-results.json').read_text())
a=request('/assessments/'+saved['demo_id'])
assert len(a['findings'])==saved['demo_count']
assert request('/reports/'+a['id'])['assessment']['security_score']==a['security_score']
print('PASS: completed findings and report survive process restart.',flush=True)
gitleaks=ROOT/'.tooling/gitleaks/gitleaks.exe';off=gitleaks.with_suffix('.qa-disabled')
gitleaks.rename(off)
try:
 a=scan((ROOT/'demo/cyberguard-vulnerable-demo.zip').read_bytes(),'Unavailable scanner QA')
 assert next(r for r in a['scanner_runs'] if r['scanner']=='Gitleaks')['status']=='Unavailable'
 assert not any(f['scanner']=='Gitleaks' for f in a['findings'])
 assert any(f['scanner']=='Semgrep' for f in a['findings'])
 print('PASS: Gitleaks unavailable; Semgrep findings retained; honest coverage warning.',flush=True)
 semgrep=ROOT/'.venv/Scripts/semgrep.exe';semoff=semgrep.with_suffix('.qa-disabled');semgrep.rename(semoff)
 try:
  a=upload((ROOT/'demo/cyberguard-vulnerable-demo.zip').read_bytes(),name='All unavailable QA')
  request('/assessments/'+a['id']+'/start','POST')
  deadline=time.monotonic()+30
  while time.monotonic()<deadline:
   a=request('/assessments/'+a['id'])
   if a['status']=='Failed':break
   time.sleep(.5)
  assert a['status']=='Failed' and a['security_score'] is None and a['findings']==[]
  print('PASS: all unavailable yields Failed, no score and zero findings.',flush=True)
 finally:semoff.rename(semgrep)
finally:off.rename(gitleaks)

