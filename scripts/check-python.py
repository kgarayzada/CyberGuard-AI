import importlib.util
import sys
sys.exit(0 if sys.version_info >= (3, 10) and all(importlib.util.find_spec(module) for module in ("fastapi", "uvicorn")) else 1)
