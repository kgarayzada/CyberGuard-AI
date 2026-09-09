"""Integration QA against running loopback services. Creates one scan and a saved report.
Run reset-demo.ps1 after verification to restore the presentation state.
"""
import json
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3

BASE = "http://127.0.0.1:5173/api"

def request(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE+path, data=data, method=method, headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=15) as response: return json.load(response)

def run():
    s = request("/state")
    assert s["summary"]["score"] == 58
    assert s["summary"]["severity"] == {"CRITICAL":1,"HIGH":3,"MEDIUM":4,"LOW":2}
    assert s["summary"]["resolved"] == 1
    assert len(s["paths"]) == 2
    assert s["asset"]["url"] == "https://portal.fintrust-demo.local"
    for f in s["findings"]:
        detail = request("/findings/"+f["id"])
        assert len(detail["analysis"]) == 6
        assert sum(x["value"] for x in detail["factors"]) == detail["risk"]
    assert [f["risk"] for f in s["findings"][:4]] == [96,86,81,84]
    print("PASS: Seeded asset, severity distribution, all finding details and exact risk breakdowns")
    for question in s["questions"]:
        answer = request("/analyst","POST",{"question":question})
        assert answer["sections"] and "local" in answer["method"]
    print("PASS: All six analyst questions use database context")
    before_count = len(s["scans"])
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda _:request("/scans","POST"),range(3)))
    assert len(set(r["id"] for r in results)) == 1, "Concurrent starts must reuse the active scan"
    scan = results[0]
    observed = [scan["progress"]]
    while time.monotonic()-started < 12:
        scan=request("/scans/"+scan["id"])
        observed.append(scan["progress"])
        if scan["status"] == "COMPLETED": break
        time.sleep(.3)
    elapsed = time.monotonic()-started
    assert scan["status"] == "COMPLETED"
    assert 5 <= elapsed <= 9, elapsed
    assert scan["progress"] == 100 and len(set(observed)) > 6
    assert observed == sorted(observed)
    assert len(scan["findings"]) == 11
    assert len(request("/state")["scans"]) == before_count+1
    db=Path(__file__).resolve().parents[1]/"data"/"cyberguard.db"
    with sqlite3.connect(db) as c:
        row=c.execute("SELECT status,findings FROM scans WHERE id=?",(scan["id"],)).fetchone()
        assert row[0]=="COMPLETED" and len(json.loads(row[1]))==11
    print(f"PASS: Concurrent scan start, monotonic progress, completion in {elapsed:.1f}s and SQLite snapshot")
    report=request("/reports","POST")
    assert report["assessment"]["id"]==scan["id"]
    assert len(report["priorities"]["sections"])==5
    fid="CG-F001"
    try:
        for status in ["ACCEPTED","FALSE POSITIVE","RESOLVED"]:
            assert request('/findings/'+fid,'PATCH',{'status':status})['status']==status
            assert len(request('/state')['paths'])==1
        assert request('/reports/'+report['id'])['summary']['open']==10
        assert request('/reports/current')['summary']['open']==9
        assert request('/scans/'+scan['id'])['findings'][0]['status']=='OPEN'
    finally: request('/findings/'+fid,'PATCH',{'status':'OPEN'})
    try:
        request('/findings/'+fid,'PATCH',{'status':'INVALID'})
        raise AssertionError('Invalid disposition was accepted')
    except urllib.error.HTTPError as error: assert error.code==422
    print('PASS: Dispositions, path recalculation, immutable scan/report snapshots and validation')
    print('API INTEGRATION QA PASSED')

if __name__=='__main__': run()
