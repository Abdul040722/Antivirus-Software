# MalDefender

MalDefender is a customizable antivirus software developed as part of my **SAIT capstone project**.
This branch represents **my specific work**, separate from my teammates. The goal was to design an antivirus solution that can be **completely customized** by the user—covering GUI, CLI, real-time protection, YARA rules, and behavior monitoring.

``` bash
Antivirus-Software/
├── run_maldefender.py
├── .vscode/
│   ├── c_cpp_properties.json
│   ├── launch.json
│   └── settings.json
├── maldefender/
│   ├── __init__.py
│   ├── app_config.py
│   ├── app_logger.py
│   ├── archive_scanner.py
│   ├── behavior_engine.py
│   ├── cli.py
│   ├── file_utils.py
│   ├── gui.py
│   ├── malware_scanner.py
│   ├── realtime_monitor.py
│   ├── reputation_cache.py
│   ├── rollback_journal.py
│   ├── scan_cache.py
│   ├── scheduler.py
│   ├── signature_db.py
│   ├── visualizer.py
│   ├── yara_scanner.py
│   └── yara_rules/
│       └── maldefender_rules.yar
├── Test/
│   ├── benign_behavior_trigger.py
│   └── test_behavior_engine.py
└── README
```

---

## 📦 Requirements

### Runtime

* Python 3.9+ (tested on Linux & Windows 10)
* Tkinter (for GUI mode)
* Pip package manager available

### Python Dependencies

The program ensures dependencies are installed automatically when running `run_maldefender.py`.
Core libraries:

* `watchdog` – filesystem monitoring
* `rarfile` – RAR archive support
* `yara-python` – YARA scanning
* `psutil` – process/network monitoring
* `python-crontab` – scheduling scans (Linux/macOS only)

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/Abdul040722/Antivirus-Software/tree/Abdul
cd Antivirus-Software

# (Optional) Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

# Run the launcher (will install deps if missing)
python run_maldefender.py
```

---

## 🚀 Usage

### Graphical User Interface (GUI)

```bash
python run_maldefender.py --gui
```

If no arguments are provided and Tkinter is available, the GUI launches automatically.

**Features in GUI:**

* Dashboard: real-time status & recent detections
* Scan tab: quick scan, full system, or custom paths
* Real-time monitoring: enable/disable, manage paths
* Quarantine: view, restore, or delete threats
* Signature management: import/export, add new hashes
* Logs: real-time logging with copy/export support

---

### Command-Line Interface (CLI)

```bash
python run_maldefender.py --help
```

Examples:

```bash
# Scan Downloads folder
python run_maldefender.py --scan ~/Downloads

# Scan a file and quarantine if infected
python run_maldefender.py ~/suspicious.exe --auto-action quarantine

# Start real-time protection + behavior monitoring
python run_maldefender.py --realtime start --behavior start

# Add a new SHA256 signature
python run_maldefender.py --add-signature <hash> --hash-type sha256
```

---

## 🛡 Capabilities

* **Signature Scanning**

  * MD5 & SHA256-based detection
  * JSON or SQLite backend
* **Archive Scanning**

  * Safe extraction for `.zip` and `.rar`
* **YARA Integration**

  * Customizable rules in `maldefender/yara_rules/`
  * Rule metadata scoring
* **Behavioral Engine**

  * Detects suspicious activity: LOLBins, encoded PowerShell, ransomware-like bursts, unusual network patterns, and parent-child process chains
  * Supports allowlist, denylist, and local reputation cache
* **Real-Time Monitoring**

  * Watches user-selected directories with debounce & stability checks
* **Quarantine & Rollback**

  * Isolate infected files
  * Rollback recent file creations on incidents
* **Scheduler**

  * Daily scan scheduling via cron (Linux/macOS)
* **Cross-Platform GUI**

  * Tkinter interface with theming, tabs for scanning, signatures, quarantine, and logs
* **Logging**

  * Rotating logs to `~/.maldefender/malware_scan.log`

---

## ⚠️ Limitations

* **No kernel-level hooks**: Limited to user-space monitoring (cannot intercept syscalls).
* **Archive support**: Only ZIP and RAR supported. Password-protected RARs are skipped.
* **Scheduling**: Uses `crontab` (not available on Windows).
* **Rollback**: Only handles created files (not full system rollback).
* **False positives/negatives**: Behavior engine may misclassify unusual but legitimate activity.
* **Performance**: Scanning very large directories/files may be slow due to Python’s overhead.
