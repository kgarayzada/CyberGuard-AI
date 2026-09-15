"""Focused security-boundary tests; use only synthetic inputs."""
import io,tempfile,zipfile,unittest,stat
from pathlib import Path
from unittest.mock import patch
from backend.archive import extract,ArchiveError
from backend.engine import normalize,security_score
from backend.scanners import run_local
class Boundaries(unittest.TestCase):
 def archive(self,name='ok.py',content='pass',mode=None,encrypted=False):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:
   i=zipfile.ZipInfo(name)
   if mode:i.external_attr=mode<<16
   z.writestr(i,content)
  data=bytearray(b.getvalue())
  if encrypted:
   data[6]|=1;central=data.index(b'PK\x01\x02');data[central+8]|=1
  return data
 def reject(self,data):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'a.zip').write_bytes(data)
   with self.assertRaises(ArchiveError):extract(p/'a.zip',p/'source')
 def test_unsafe_names(self):
  for n in ('../a','/a','C:/a','a:b','NUL.py','trailing.','x/../../a'):
   with self.subTest(n=n):self.reject(self.archive(n))
 def test_backslash(self):self.reject(self.archive('x/a').replace(b'x/a',b'x'+bytes([92])+b'a'))
 def test_symlink(self):self.reject(self.archive(mode=stat.S_IFLNK|0o777))
 def test_encrypted(self):self.reject(self.archive(encrypted=True))
 def test_file_count(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:
   for i in range(2001):z.writestr(str(i),'x')
  self.reject(b.getvalue())
 def test_case_collision(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:z.writestr('a','x');z.writestr('A','x')
  self.reject(b.getvalue())
 def test_unavailable_no_findings(self):
  with patch('backend.scanners.executable',return_value=Path('nonexistent-scanner')):
   fs,status,_,_=run_local('Gitleaks',{'id':'test'},Path('.'))
   self.assertEqual(fs,[]);self.assertEqual(status,'Unavailable')
 def test_scoring_context_and_dedup(self):
  f=normalize({'id':'one'},'scanner','rule','title','HIGH','SQL Injection','a.py',1)
  g=normalize({'id':'two','environment':'Production','criticality':'High'},'scanner','rule','title','HIGH','SQL Injection','a.py',1)
  self.assertEqual(f['fingerprint'],g['fingerprint']);self.assertEqual(g['contextual_risk_score']-f['contextual_risk_score'],8)
  self.assertEqual(security_score([]),100);self.assertGreater(security_score([f]),security_score([g]))
if __name__=='__main__':unittest.main()
