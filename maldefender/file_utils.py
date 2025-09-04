# maldefender/file_utils.py
import hashlib
import os
from pathlib import Path
from typing import Dict, Tuple, Optional
import threading


_READ_CHUNK = 1024 * 1024  # 1 MiB


class _HasherPool:
    """Reusable hasher constructors to avoid branching in tight loops."""
    @staticmethod
    def md5():
        try:
            return hashlib.md5()
        except Exception:
            return None

    @staticmethod
    def sha1():
        try:
            return hashlib.sha1()
        except Exception:
            return None

    @staticmethod
    def sha256():
        try:
            return hashlib.sha256()
        except Exception:
            return None
    

class FileHasher:
    """File hashing utility with both MD5 and SHA256"""
    _lock = threading.Lock()

    @staticmethod
    def fast_fingerprint(file_path: Path, first_bytes: int = 64 * 1024) -> Optional[str]:
        """
        Return a fast fingerprint (SHA256 of first N bytes). Used for cache keys.
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read(max(1024, int(first_bytes)))
            h = hashlib.sha256()
            h.update(data)
            return h.hexdigest()
        except PermissionError:
            return None
        except Exception:
            return None

    @staticmethod
    def get_hashes_multi(
        file_path: Path,
        *,
        want_md5: bool = True,
        want_sha1: bool = False,
        want_sha256: bool = True,
    ) -> Dict[str, Optional[str]]:
        """
        Stream the file once and compute requested hashes.
        Returns a dict with keys among {"md5", "sha1", "sha256"}.
        """
        res: Dict[str, Optional[str]] = {"md5": None, "sha1": None, "sha256": None}

        try:
            md5_h = _HasherPool.md5() if want_md5 else None
            sha1_h = _HasherPool.sha1() if want_sha1 else None
            sha256_h = _HasherPool.sha256() if want_sha256 else None

            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
                    if md5_h is not None:
                        md5_h.update(chunk)
                    if sha1_h is not None:
                        sha1_h.update(chunk)
                    if sha256_h is not None:
                        sha256_h.update(chunk)

            if md5_h is not None:
                res["md5"] = md5_h.hexdigest()
            if sha1_h is not None:
                res["sha1"] = sha1_h.hexdigest()
            if sha256_h is not None:
                res["sha256"] = sha256_h.hexdigest()

            return res
        except PermissionError:
            return res
        except Exception:
            return res
    
    @staticmethod
    def get_hashes(file_path: Path) -> Tuple[Optional[str], Optional[str]]:
        """Calculate MD5 and SHA256 hashes of a file"""
        out = FileHasher.get_hashes_multi(file_path, want_md5=True, want_sha1=False, want_sha256=True)
        return out.get("md5"), out.get("sha256")
