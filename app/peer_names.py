"""Peer display name management."""
from __future__ import annotations

import json
import os
import threading
from typing import Dict, Optional

from config import Config


class PeerNameStore:
    """Manages human-readable aliases for WireGuard peer public keys."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def _save(self) -> None:
        with open(self._path, "w") as f:
            json.dump(self._data, f, indent=2)

    def get_all(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._data)

    def get(self, public_key: str) -> Optional[str]:
        with self._lock:
            return self._data.get(public_key)

    def set(self, public_key: str, name: str) -> None:
        with self._lock:
            self._data[public_key] = name
            self._save()

    def delete(self, public_key: str) -> bool:
        with self._lock:
            if public_key in self._data:
                del self._data[public_key]
                self._save()
                return True
            return False


_peer_name_store: Optional[PeerNameStore] = None


def get_peer_name_store() -> PeerNameStore:
    global _peer_name_store
    if _peer_name_store is None:
        _peer_name_store = PeerNameStore(Config.PEER_NAMES_FILE)
    return _peer_name_store
