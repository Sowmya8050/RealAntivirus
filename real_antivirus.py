import os
import sys
import hashlib
import json
import shutil
import time
import logging
import csv
import argparse
from datetime import datetime
from pathlib import Path
from math import log2

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception:
    tk = None

# Optional: watchdog for real-time monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

# -------------------------
# Config & Constants
# -------------------------
PROJECT_ROOT = Path(__file__).parent.resolve()
LOG_DIR = PROJECT_ROOT / "logs"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
SIGNATURES_FILE = PROJECT_ROOT / "signatures.json"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

SCAN_LOG = LOG_DIR / "scans.log"
ACTIONS_CSV = LOG_DIR / "actions.csv"

# Configure Python logger
logger = logging.getLogger("RealAntivirus")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(SCAN_LOG, encoding="utf-8")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# Also print to console
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)

# -------------------------
# Utilities
# -------------------------

def compute_hash(path, algorithm="sha256", block_size=65536):
    h = hashlib.new(algorithm)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(block_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning(f"Failed hashing {path}: {e}")
        return None

def file_entropy(path):
    """Compute byte entropy of a file (simple Shannon entropy)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        ent = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            ent -= p * log2(p)
        return ent
    except Exception as e:
        logger.warning(f"Entropy failed for {path}: {e}")
        return 0.0

def write_action_csv(action_row):
    header = ["timestamp", "action", "file_path", "reason", "hash", "quarantine_path"]
    write_header = not ACTIONS_CSV.exists()
    try:
        with open(ACTIONS_CSV, "a", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(header)
            writer.writerow(action_row)
    except Exception as e:
        logger.error(f"Failed writing actions CSV: {e}")

# -------------------------
# SignatureDB
# -------------------------
class SignatureDB:
    def __init__(self, path=SIGNATURES_FILE):
        self.path = Path(path)
        self.signatures = []
        self.whitelist = []
        self.suspicious_extensions = []
        self.load()

    def load(self):
        if not self.path.exists():
            logger.warning(f"Signatures file not found: {self.path}. Creating default.")
            default = {"signatures": [], "whitelist": [], "suspicious_extensions": [".exe", ".bat", ".scr", ".js", ".vbs"]}
            self.path.write_text(json.dumps(default, indent=2))
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.signatures = data.get("signatures", [])
            self.whitelist = data.get("whitelist", [])
            self.suspicious_extensions = data.get("suspicious_extensions", [])
            logger.info(f"Loaded {len(self.signatures)} signatures and {len(self.whitelist)} whitelist entries.")
        except Exception as e:
            logger.error(f"Error loading signatures.json: {e}")
            self.signatures = []
            self.whitelist = []
            self.suspicious_extensions = []

    def match_hash(self, file_hash):
        if not file_hash:
            return None
        for sig in self.signatures:
            if sig.get("type") == "hash" and sig.get("hash") and sig.get("algorithm", "sha256") and sig.get("algorithm","sha256").lower() in ("sha256","sha1","md5"):
                if sig["hash"].lower() == file_hash.lower():
                    return sig
        return None

    def is_whitelisted(self, file_hash):
        if not file_hash:
            return False
        for w in self.whitelist:
            if w.get("hash") and w.get("algorithm", "sha256"):
                if w["hash"].lower() == file_hash.lower():
                    return True
        return False

    def match_pattern_in_file(self, file_path):
        # search for textual signature pattern (small files preferred)
        try:
            with open(file_path, "rb") as f:
                data = f.read(2000000)  # read up to 2MB for scanning
            text = None
            try:
                text = data.decode('utf-8', errors='ignore')
            except:
                text = None
            for sig in self.signatures:
                if sig.get("type") == "pattern" and sig.get("pattern"):
                    pat = sig["pattern"]
                    if text and pat in text:
                        return sig
            return None
        except Exception as e:
            logger.debug(f"Pattern match read error for {file_path}: {e}")
            return None

# -------------------------
# Heuristic Analyzer
# -------------------------
class HeuristicAnalyzer:
    def __init__(self, sigdb: SignatureDB):
        self.sigdb = sigdb

    def analyze(self, file_path, file_hash=None):
        """Return (is_suspicious: bool, reasons: list[str])"""
        reasons = []
        # Suspicious extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in [e.lower() for e in self.sigdb.suspicious_extensions]:
            reasons.append(f"suspicious_extension:{ext}")
        # Entropy suspicious for executables ( >7.5 is often packed)
        try:
            ent = file_entropy(file_path)
            if ent > 7.5:
                reasons.append(f"high_entropy:{ent:.2f}")
        except Exception:
            pass
        # Text-based suspicious strings
        suspicious_markers = ["eval(", "base64", "CreateRemoteThread", "WinExec", "MZ"]  # MZ for PE header
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(200000)  # 200 KB
            txt = chunk.decode('utf-8', errors='ignore').lower()
            for marker in suspicious_markers:
                if marker.lower() in txt:
                    reasons.append(f"suspicious_string:{marker}")
        except Exception:
            pass

        # small heuristic: many files flagged as suspicious if multiple reasons
        if reasons:
            return True, reasons
        return False, []

# -------------------------
# Quarantine Manager
# -------------------------
class QuarantineManager:
    def __init__(self, base_dir=QUARANTINE_DIR):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)

    def quarantine(self, file_path):
        file_path = Path(file_path)
        if not file_path.exists():
            return None
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self.base / f"{file_path.name}__{ts}"
        try:
            shutil.move(str(file_path), str(dest))
            logger.info(f"Quarantined {file_path} -> {dest}")
            write_action_csv([datetime.now().isoformat(), "quarantine", str(file_path), "", compute_hash(dest), str(dest)])
            return str(dest)
        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return None

    def restore(self, quarantined_path, original_path):
        try:
            shutil.move(quarantined_path, original_path)
            logger.info(f"Restored {quarantined_path} -> {original_path}")
            write_action_csv([datetime.now().isoformat(), "restore", str(original_path), "", compute_hash(original_path), str(quarantined_path)])
            return True
        except Exception as e:
            logger.error(f"Failed to restore {quarantined_path}: {e}")
            return False

# -------------------------
# File Scanner
# -------------------------
class FileScanner:
    def __init__(self, sigdb: SignatureDB, heuristic: HeuristicAnalyzer, quarantine_mgr: QuarantineManager):
        self.sigdb = sigdb
        self.heuristic = heuristic
        self.quarantine_mgr = quarantine_mgr

    def scan_path(self, root_path, recursive=True, callback=None):
        """
        Scan files under root_path.
        callback(file_path, result_dict) -> optional for GUI progress updates
        returns list of detections
        """
        detections = []
        root = Path(root_path)
        if root.is_file():
            iterable = [root]
        else:
            if recursive:
                iterable = root.rglob('*')
            else:
                iterable = root.iterdir()

        for p in iterable:
            if p.is_file():
                try:
                    res = self.scan_file(p)
                    if callback:
                        callback(str(p), res)
                    if res["infected"]:
                        detections.append(res)
                except Exception as e:
                    logger.debug(f"Failed scanning {p}: {e}")
        logger.info(f"Scan completed for {root_path}. Detections: {len(detections)}")
        return detections

    def scan_file(self, file_path):
        file_path = Path(file_path)
        res = {
            "file": str(file_path),
            "hash": None,
            "infected": False,
            "matched_signature": None,
            "heuristic": False,
            "heuristic_reasons": [],
            "whitelisted": False,
            "actions": []
        }
        h = compute_hash(file_path)
        res["hash"] = h
        if self.sigdb.is_whitelisted(h):
            res["whitelisted"] = True
            logger.debug(f"Whitelisted: {file_path}")
            return res

        # Signature hash match
        sig = self.sigdb.match_hash(h)
        if sig:
            res["infected"] = True
            res["matched_signature"] = sig
            reason = f"signature_hash:{sig.get('name')}"
            res["actions"].append(reason)
            logger.warning(f"Signature match for {file_path} -> {sig.get('name')}")
            write_action_csv([datetime.now().isoformat(), "detected_hash", str(file_path), sig.get("name"), h, ""])
            return res

        # Pattern matching
        pat = self.sigdb.match_pattern_in_file(file_path)
        if pat:
            res["infected"] = True
            res["matched_signature"] = pat
            res["actions"].append(f"signature_pattern:{pat.get('name')}")
            logger.warning(f"Pattern signature match for {file_path} -> {pat.get('name')}")
            write_action_csv([datetime.now().isoformat(), "detected_pattern", str(file_path), pat.get("name"), h, ""])
            return res

        # Heuristic analysis
        heur, reasons = self.heuristic.analyze(str(file_path), file_hash=h)
        if heur:
            res["infected"] = True
            res["heuristic"] = True
            res["heuristic_reasons"] = reasons
            res["actions"].extend(reasons)
            logger.warning(f"Heuristic suspicious: {file_path} reasons: {reasons}")
            write_action_csv([datetime.now().isoformat(), "detected_heuristic", str(file_path), ";".join(reasons), h, ""])
            return res

        # Clean
        logger.debug(f"Clean file: {file_path}")
        write_action_csv([datetime.now().isoformat(), "clean", str(file_path), "", h, ""])
        return res

# -------------------------
# Simple Console Interface (for CLI)
# -------------------------
def cli_scan(folder, recursive=True, auto_quarantine=False):
    sigdb = SignatureDB()
    heur = HeuristicAnalyzer(sigdb)
    qm = QuarantineManager()
    scanner = FileScanner(sigdb, heur, qm)
    start = time.time()
    detections = scanner.scan_path(folder, recursive=recursive, callback=lambda f,r: print(f"Scanned {f} -> {('INFECTED' if r['infected'] else 'clean')}"))
    elapsed = time.time()-start
    print(f"Scan finished in {elapsed:.1f}s. {len(detections)} detections found.")
    if auto_quarantine and detections:
        for d in detections:
            qpath = qm.quarantine(d["file"])
            print(f"Quarantined {d['file']} -> {qpath}")
    return detections

# -------------------------
# Optional Watchdog Monitor
# -------------------------
class AutoScanHandler(FileSystemEventHandler):
    def __init__(self, scanner: FileScanner, callback=None):
        super().__init__()
        self.scanner = scanner
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            path = event.src_path
            logger.info(f"File created: {path}. Auto-scanning.")
            res = self.scanner.scan_file(path)
            if self.callback:
                self.callback(path, res)

def start_monitor(path, scanner: FileScanner, callback=None):
    if not WATCHDOG_AVAILABLE:
        logger.warning("Watchdog not available. Install with: pip install watchdog")
        return None
    event_handler = AutoScanHandler(scanner, callback=callback)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    logger.info(f"Started monitoring {path} for changes.")
    return observer

# -------------------------
# GUI (Tkinter)
# -------------------------
class AVGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RealAntivirus (Educational)")
        self.sigdb = SignatureDB()
        self.heur = HeuristicAnalyzer(self.sigdb)
        self.qm = QuarantineManager()
        self.scanner = FileScanner(self.sigdb, self.heur, self.qm)
        self.monitor_observer = None

        self.build_ui()

    def build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)

        # Folder selection
        hframe = ttk.Frame(frame)
        hframe.pack(fill="x", pady=4)
        self.folder_var = tk.StringVar()
        entry = ttk.Entry(hframe, textvariable=self.folder_var)
        entry.pack(side="left", fill="x", expand=True)
        btn_browse = ttk.Button(hframe, text="Browse...", command=self.browse)
        btn_browse.pack(side="left", padx=4)
        btn_scan = ttk.Button(hframe, text="Scan", command=self.start_scan_threaded)
        btn_scan.pack(side="left", padx=4)

        # Monitor toggle
        self.monitor_var = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(frame, text="Real-time monitor (requires watchdog)", variable=self.monitor_var, command=self.toggle_monitor)
        chk.pack(anchor="w", pady=4)

        # Results tree
        self.tree = ttk.Treeview(frame, columns=("status","hash","reasons"), show="headings", height=15)
        self.tree.heading("status", text="Status")
        self.tree.heading("hash", text="Hash (sha256)")
        self.tree.heading("reasons", text="Reasons / Signature")
        self.tree.column("status", width=90)
        self.tree.column("hash", width=300)
        self.tree.column("reasons", width=400)
        self.tree.pack(fill="both", expand=True, pady=4)

        # Buttons for actions
        bframe = ttk.Frame(frame)
        bframe.pack(fill="x")
        btn_quarantine = ttk.Button(bframe, text="Quarantine Selected", command=self.quarantine_selected)
        btn_quarantine.pack(side="left", padx=4)
        btn_delete = ttk.Button(bframe, text="Delete Selected", command=self.delete_selected)
        btn_delete.pack(side="left", padx=4)
        btn_refresh = ttk.Button(bframe, text="Refresh Signatures", command=self.reload_signatures)
        btn_refresh.pack(side="right", padx=4)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w")
        status.pack(side="bottom", fill="x")

    def browse(self):
        d = filedialog.askdirectory()
        if d:
            self.folder_var.set(d)

    def reload_signatures(self):
        self.sigdb.load()
        messagebox.showinfo("Signatures", "Signatures reloaded.")

    def update_status(self, text):
        self.status_var.set(text)
        self.root.update_idletasks()

    def start_scan_threaded(self):
        folder = self.folder_var.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Please select a valid folder to scan.")
            return
        # disable buttons?
        self.clear_tree()
        self.update_status("Scanning...")
        self.root.after(100, lambda: self.run_scan(folder))

    def run_scan(self, folder):
        # run scan synchronously but return control to UI with after() to avoid total freeze (simple approach)
        def callback(file_path, result):
            # called for each file scanned
            status = "INFECTED" if result["infected"] else "clean"
            reason = ""
            if result["infected"]:
                if result["matched_signature"]:
                    reason = f"sig:{result['matched_signature'].get('name')}"
                elif result["heuristic"]:
                    reason = ";".join(result.get("heuristic_reasons", []))
            self.tree.insert("", "end", values=(status, result.get("hash",""), reason))
            self.update_status(f"Scanning {file_path}")
        self.scanner.scan_path(folder, recursive=True, callback=callback)
        self.update_status("Scan complete.")

    def clear_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

    def get_selected_files(self):
        sel = self.tree.selection()
        files = []
        for s in sel:
            # we stored only values, but not file path. For simplicity, we will map hash->file by reading logs/actions.csv recent lines.
            vals = self.tree.item(s, "values")
            # values: status, hash, reasons
            files.append({'status': vals[0], 'hash': vals[1], 'reasons': vals[2]})
        return files

    def quarantine_selected(self):
        # map hashes to last scanned file path by reading actions.csv
        sel = self.get_selected_files()
        if not sel:
            messagebox.showinfo("Select", "No selection.")
            return
        mapping = self._map_hash_to_path()
        for item in sel:
            h = item['hash']
            path = mapping.get(h)
            if path:
                dest = self.qm.quarantine(path)
                messagebox.showinfo("Quarantine", f"Quarantined {path} -> {dest}")
            else:
                messagebox.showwarning("Not Found", f"Could not find file path for hash {h}. Try scanning again or check logs.")

    def delete_selected(self):
        sel = self.get_selected_files()
        if not sel:
            messagebox.showinfo("Select", "No selection.")
            return
        mapping = self._map_hash_to_path()
        for item in sel:
            h = item['hash']
            path = mapping.get(h)
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                    write_action_csv([datetime.now().isoformat(), "deleted", str(path), item['reasons'], h, ""])
                    messagebox.showinfo("Deleted", f"Deleted {path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete {path}: {e}")
            else:
                messagebox.showwarning("Not Found", f"Could not find file path for hash {h}.")

    def _map_hash_to_path(self):
        """Reconstruct a mapping of last scanned hash->file path from actions.csv"""
        mapping = {}
        try:
            if ACTIONS_CSV.exists():
                with open(ACTIONS_CSV, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        # keep last occurrence
                        mapping[row.get("hash","")] = row.get("file_path","")
        except Exception as e:
            logger.debug(f"Mapping hashes failed: {e}")
        return mapping

    def toggle_monitor(self):
        folder = self.folder_var.get()
        if not folder or not os.path.exists(folder):
            messagebox.showerror("Error", "Choose a folder to monitor first.")
            self.monitor_var.set(False)
            return
        if self.monitor_var.get():
            # start monitoring
            if not WATCHDOG_AVAILABLE:
                messagebox.showerror("Missing Package", "Install watchdog: pip install watchdog")
                self.monitor_var.set(False)
                return
            if self.monitor_observer:
                messagebox.showinfo("Monitor", "Already monitoring.")
                return
            obs = start_monitor(folder, self.scanner, callback=self._monitor_callback)
            self.monitor_observer = obs
            self.update_status(f"Monitoring {folder}")
        else:
            # stop
            if self.monitor_observer:
                self.monitor_observer.stop()
                self.monitor_observer.join(timeout=1)
                self.monitor_observer = None
                self.update_status("Monitoring stopped.")

    def _monitor_callback(self, path, result):
        # show pop-up for suspicious files
        if result["infected"]:
            messagebox.showwarning("Real-time Alert", f"Suspicious file detected: {path}\nReasons: {result.get('heuristic_reasons') or result.get('matched_signature')}")
            # insert into tree
            reason = ""
            if result.get("matched_signature"):
                reason = f"sig:{result['matched_signature'].get('name')}"
            elif result.get("heuristic"):
                reason = ";".join(result.get("heuristic_reasons", []))
            self.tree.insert("", "end", values=("INFECTED", result.get("hash",""), reason))
        else:
            # optionally show minor info
            self.tree.insert("", "end", values=("clean", result.get("hash",""), ""))

# -------------------------
# Main Driver
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="RealAntivirus (educational) - scan files for signatures and heuristics.")
    parser.add_argument("--scan", help="Scan folder or file (CLI).")
    parser.add_argument("--no-recursive", action="store_true", help="Do not recurse directories.")
    parser.add_argument("--auto-quarantine", action="store_true", help="Automatically quarantine detected files (CLI).")
    parser.add_argument("--nogui", action="store_true", help="Run CLI only (no GUI).")
    args = parser.parse_args()

    if args.scan:
        detections = cli_scan(args.scan, recursive=not args.no_recursive, auto_quarantine=args.auto_quarantine)
        # print brief summary
        for d in detections:
            print(f"[DETECT] {d['file']} -> reasons: {d['actions']}")
        return

    # default: GUI mode
    if tk is None:
        print("Tkinter not available. Use --scan for CLI.")
        return
    if args.nogui:
        print("nogui requested but no --scan provided. Exiting.")
        return

    root = tk.Tk()
    app = AVGUI(root)
    root.geometry("900x600")
    root.mainloop()

if __name__ == "__main__":
    main()
