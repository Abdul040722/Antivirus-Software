#!/usr/bin/env python
"""
Benign Behavior Engine Trigger
- Generates a high burst of file writes in a user-writable directory.
- Drops a harmless .ps1 script alongside the burst.
- Safe: writes plaintext files only; no execution of external programs; no network traffic.

Expected BehaviorEngine rule hits:
  - R6: fs.write_burst.heavy (>=200 writes within window)  -> +60
  - R5: fs.drop.exec.user (creates .ps1 in user dir)       -> +45
Total >= 105 (over default emit_threshold=80) => incident emits and engine may suspend this process.

Cleanup: remove the created folder when you’re done (instructions below).
"""

import os
import sys
import time
import shutil
from pathlib import Path

BURST_COUNT = 220            # >=200 to guarantee R6.heavy
CHUNK_BYTES = 64             # small writes to be fast and harmless
SLEEP_EVERY = 50             # tiny pause to avoid starving the system
SLEEP_SECS = 0.02

def user_downloads_dir() -> Path:
    home = Path.home()
    # Prefer Downloads on all OSes; fallback to Temp if missing.
    candidates = [
        home / "Downloads",
        Path(os.environ.get("USERPROFILE", "")) / "Downloads",
        Path(os.environ.get("HOME", "")) / "Downloads",
        Path(os.environ.get("TMP", os.getenv("TEMP", "/tmp"))),
    ]
    for c in candidates:
        try:
            if c and (c.exists() or (c.parent.exists() and not c.exists())):
                c.mkdir(parents=True, exist_ok=True)
                return c
        except Exception:
            continue
    # Ultimate fallback
    return Path.cwd()

def main() -> int:
    base_dir = user_downloads_dir() / "BEHAVIOR_TRIGGER_SAFE"
    target_dir = base_dir / "burst_files"
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1) Drop a harmless PowerShell script in a user-writable path (R5)
    ps1_path = base_dir / "benign_drop.ps1"
    ps1_path.write_text(
        "# Harmless test script used to exercise a behavior rule.\n"
        "Write-Output 'Hello from benign_drop.ps1 (test artifact)'\n",
        encoding="utf-8"
    )

    # 2) High-volume write burst to trigger R6.heavy
    payload = ("X" * CHUNK_BYTES).encode("utf-8")
    start = time.time()
    for i in range(BURST_COUNT):
        fpath = target_dir / f"artifact_{i:04d}.txt"
        with open(fpath, "wb") as f:
            f.write(payload)
        # touch/modify a second time to ensure it's counted as write activity
        with open(fpath, "ab") as f:
            f.write(b"\n")

        if (i + 1) % SLEEP_EVERY == 0:
            time.sleep(SLEEP_SECS)

    elapsed = time.time() - start
    print(f"[OK] Created {BURST_COUNT} files and benign_drop.ps1 at: {base_dir}")
    print(f"[OK] Elapsed: {elapsed:.2f}s")
    print("\nIf your BehaviorEngine + realtime monitor are running, this should emit an incident within ~seconds.")

    print("\nCLEANUP:")
    print(f"  - To remove artifacts, delete: {base_dir}")
    print("    Example (PowerShell):  Remove-Item -Recurse -Force \"$HOME\\Downloads\\BEHAVIOR_TRIGGER_SAFE\"")
    print("    Example (bash):        rm -rf \"$HOME/Downloads/BEHAVIOR_TRIGGER_SAFE\"")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
