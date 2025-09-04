"""
Thread-safe, lightweight LRU cache for file scan shortcuts.

Key:
  (path_lower, size, mtime_ns, fast64k_sha256)

Value:
  {
    "md5": str | None,
    "sha1": str | None,
    "sha256": str | None,
    "sigdb_version": int,
    "is_mal": bool | None,          # optional cached decision if version matches
    "hash_types": list[str] | None, # optional details of matched types
  }

Rationale: avoids re-hashing unchanged files and (when safe) avoids re-querying
the signature DB if its version hasn’t changed.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class ScanKey:
    path_lower: str
    size: int
    mtime_ns: int
    fast64k: str


class FileScanCache:
    def __init__(self, capacity: int = 4096):
        self.capacity = max(256, int(capacity))
        self._lock = threading.RLock()
        self._cache: "OrderedDict[ScanKey, Dict]" = OrderedDict()

    def _touch(self, key: ScanKey) -> None:
        # Move to end (MRU)
        self._cache.move_to_end(key, last=True)

    def get(self, key: ScanKey) -> Optional[Dict]:
        with self._lock:
            v = self._cache.get(key)
            if v is not None:
                self._touch(key)
            return v

    def put(self, key: ScanKey, value: Dict) -> None:
        with self._lock:
            if key in self._cache:
                self._cache[key] = value
                self._touch(key)
                return
            self._cache[key] = value
            self._touch(key)
            if len(self._cache) > self.capacity:
                # Pop LRU
                self._cache.popitem(last=False)

    @staticmethod
    def make_key(path: Path, size: int, mtime_ns: int, fast64k: str) -> ScanKey:
        return ScanKey(str(path).lower(), int(size), int(mtime_ns), fast64k)

