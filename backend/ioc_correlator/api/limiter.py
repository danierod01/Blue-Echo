import os

from slowapi import Limiter
from slowapi.util import get_remote_address

_scan_limit = os.getenv("RATE_LIMIT_SCAN", "10/minute")
_default_limit = os.getenv("RATE_LIMIT_DEFAULT", "60/minute")

limiter = Limiter(key_func=get_remote_address)
