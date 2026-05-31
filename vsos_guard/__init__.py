# -*- coding: utf-8 -*-
"""
VSOS Guard Community Edition v0.5.2

The best security plugin for the community, bar none.

v0.5.2 changes:
- Encoding variant detection: base64/unicode/hex/rot13/Leet Speak bypass detection
- Confidence 3-tier output: critical(block)/warning(alert)/safe(pass)
- GuardLogger: record every check result + reason
- Integration hooks: on_block/on_warn callbacks for easy framework integration
- Enhanced context awareness: whitelist covers more normal dev/ops scenarios
"""

from vsos_guard.guard import (
    VSOSGuard, GuardMode, CheckResult, Territory, Domain,
    Confidence, GuardLogger, EncodingDetector, normalize_text,
)

__version__ = "0.5.2"
__all__ = [
    "VSOSGuard", "GuardMode", "CheckResult", "Territory", "Domain",
    "Confidence", "GuardLogger", "EncodingDetector", "normalize_text",
]
