import os
import secrets

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    # Default admin credentials (override via env vars in production)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
    # How many historical data-points to keep per peer (5s interval × 60 = 5 min)
    MAX_HISTORY = int(os.environ.get("MAX_HISTORY", 60))
    # WireGuard interface (leave empty to auto-detect)
    WG_INTERFACE = os.environ.get("WG_INTERFACE", "")
