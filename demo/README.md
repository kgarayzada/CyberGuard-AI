# Intentionally vulnerable static fixture

This project is intentionally vulnerable and contains only synthetic test data. It is provided solely for demonstrating CyberGuard AI static security assessment.

Upload `demo/cyberguard-vulnerable-demo.zip`. Do not execute or install this fixture. It contains concatenated SQL, direct HTML assignment, MD5 usage, an unchecked constructed path, a synthetic API key and an old lodash dependency. No service or credential is real. Findings depend on actual scanner coverage and advisory availability.

The checked-in ZIP is ready to upload. Maintainers can rebuild it with `python scripts/build-demo.py` after changing `demo/source/`.
