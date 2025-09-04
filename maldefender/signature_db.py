# maldefender/signature_db.py
import json
import os
import sqlite3
import tempfile
import threading
from typing import Set, Tuple, Dict

from .app_config import config

class SignatureDatabase:
    """
    Signature database with thread-safe in-memory index and atomic persistence.

    - Primary key: SHA-256 (preferred). MD5 optionally supported for compatibility.
    - Backend: JSON (default) or optional SQLite if configured via config.
    - Version counter increments on any load/update to support cache invalidation.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._version = 0
        self._backend = getattr(config, "signatures_backend", "json").lower()
        self._sqlite_path = getattr(config, "signatures_sqlite_file", None)

        self.signatures: Dict[str, Set[str]] = {
            "md5": set(),
            "sha256": set()
        }
        self._sqlite_conn = None  # type: ignore
        if self._backend == "sqlite" and self._sqlite_path:
            try:
                self._sqlite_conn = sqlite3.connect(str(self._sqlite_path))
                self._sqlite_conn.execute(
                    "CREATE TABLE IF NOT EXISTS signatures (hash TEXT PRIMARY KEY, type TEXT NOT NULL)"
                )
                self._sqlite_conn.commit()
            except Exception:
                # Fallback to JSON quietly if sqlite unavailable
                self._backend = "json"
                self._sqlite_conn = None
        self.load_signatures()

    @property
    def version(self) -> int:
        with self._lock:
            return self._version
    
    def load_signatures(self):
        """Load signatures from configured backend into memory."""
        with self._lock:
            try:
                if self._backend == "sqlite" and self._sqlite_conn is not None:
                    md5s: Set[str] = set()
                    sha256s: Set[str] = set()
                    cur = self._sqlite_conn.execute("SELECT hash, type FROM signatures")
                    for h, t in cur.fetchall():
                        hh = (h or "").lower()
                        tt = (t or "").lower()
                        if tt == "md5":
                            md5s.add(hh)
                        elif tt == "sha256":
                            sha256s.add(hh)
                    self.signatures["md5"] = md5s
                    self.signatures["sha256"] = sha256s
                else:
                    if config.signatures_file.exists():
                        with open(config.signatures_file, encoding="utf-8") as f:
                            data = json.load(f)
                        self.signatures["md5"] = set([str(x).lower() for x in data.get("md5", [])])
                        self.signatures["sha256"] = set([str(x).lower() for x in data.get("sha256", [])])
                    else:
                        self.signatures = {"md5": set(), "sha256": set()}
                        self.save_signatures()
                self._version += 1
            except Exception as e:
                print(f"Error loading signatures: {e}")
    
    def save_signatures(self):
        """Save signatures atomically (JSON backend)."""
        with self._lock:
            if self._backend == "sqlite" and self._sqlite_conn is not None:
                return  # SQLite writes happen per-insert
            try:
                data = {
                    "md5": sorted(self.signatures["md5"]),
                    "sha256": sorted(self.signatures["sha256"])
                }
                target = config.signatures_file
                target.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("w", delete=False, dir=str(target.parent), encoding="utf-8") as tf:
                    json.dump(data, tf, indent=2)
                    tf.flush()
                    os.fsync(tf.fileno())
                    tmp = tf.name
                os.replace(tmp, target)
            except Exception as e:
                print(f"Error saving signatures: {e}")
    
    def add_signature(self, signature: str, hash_type: str = "sha256"):
        """Add a new signature (lowercased) and persist to backend."""
        sig = (signature or "").lower()
        ht = (hash_type or "sha256").lower()
        if ht not in {"md5", "sha256"} or not sig:
            return
        with self._lock:
            if self._backend == "sqlite" and self._sqlite_conn is not None:
                try:
                    self._sqlite_conn.execute(
                        "INSERT OR IGNORE INTO signatures(hash, type) VALUES(?, ?)", (sig, ht)
                    )
                    self._sqlite_conn.commit()
                except Exception:
                    pass
                self.signatures[ht].add(sig)
                self._version += 1
                return
            # JSON backend
            self.signatures[ht].add(sig)
            self.save_signatures()
            self._version += 1
    
    def is_malicious(self, md5_hash: str, sha256_hash: str) -> Tuple[bool, list]:
        """Check if hashes match any malicious signatures. Returns all matching types."""
        with self._lock:
            matches = []
            if md5_hash and md5_hash.lower() in self.signatures["md5"]:
                matches.append("MD5")
            if sha256_hash and sha256_hash.lower() in self.signatures["sha256"]:
                matches.append("SHA256")
            return (len(matches) > 0, matches)
