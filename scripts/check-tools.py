import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.scanners import availability
for item in availability():
    print(item['scanner']+': '+(item.get('version') or 'unavailable'))
