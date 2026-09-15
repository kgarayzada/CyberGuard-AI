from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
root=Path(__file__).resolve().parents[1]
with ZipFile(root/'demo/cyberguard-vulnerable-demo.zip','w',ZIP_DEFLATED) as z:
    for p in sorted((root/'demo/source').rglob('*')):
        if p.is_file():z.write(p,p.relative_to(root/'demo/source').as_posix())
    z.write(root/'demo/README.md','README.md')
print('Demo ZIP ready.')
