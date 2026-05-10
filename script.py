gui_code = '''#!/usr/bin/env python3
"""
Forensic Tool GUI — CET333 Advanced Digital Forensics
Elsewedy University of Technology | Dr. Ayman Taha
"""

import sys
import os
import csv
import json
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
    QProgressBar, QTextEdit, QTabWidget, QHeaderView, QFrame,
    QSplitter, QStatusBar, QMessageBox, QGroupBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon

import exifread
import pandas as pd
from PIL import Image


# ─────────────────────────────────────────────
# UTILITIES (same as forensic_tool.py)
# ─────────────────────────────────────────────

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_ratio(value):
    s = str(value)
    if "/" in s:
        a, b = s.split("/")
        return float(a) / float(b) if float(b) != 0 else 0.0
    return float(s)

def dms_to_decimal(dms_tag, ref_tag):
    try:
        parts = [p.strip() for p in str(dms_tag).replace("[","").replace("]","").split(",")]
        if len(parts) != 3:
            return None
        dec = parse_ratio(parts[0]) + parse_ratio(parts[1])/60 + parse_ratio(parts[2])/3600
        if str(ref_tag).strip() in ["S", "W"]:
            dec = -dec
        return round(dec, 7)
    except Exception:
        return None

def ts_to_iso(ts):
    try:
        return datetime.strptime(str(ts), "%Y:%m:%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None

def extract_record(image_path):
    path_str = str(image_path)
    file_hash = sha256_file(path_str)
    file_size = os.path.getsize(path_str)
    tags = {}
    anomalies = []

    try:
        with Image.open(path_str) as im:
            fmt = im.format
            img_width, img_height = im.size
    except Exception:
        fmt, img_width, img_height = "UNKNOWN", None, None

    if fmt == "PNG":
        anomalies.append("PNG format — EXIF/GPS rarely present")
    else:
        try:
            with open(path_str, "rb") as f:
                raw = exifread.process_file(f, details=False)
            tags = {str(k): str(v) for k, v in raw.items()}
        except Exception as e:
            anomalies.append(f"EXIF read error: {e}")

    timestamp  = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")
    make       = tags.get("Image Make")
    model      = tags.get("Image Model")
    software   = tags.get("Image Software")
    lat = dms_to_decimal(tags.get("GPS GPSLatitude"),  tags.get("GPS GPSLatitudeRef"))
    lon = dms_to_decimal(tags.get("GPS GPSLongitude"), tags.get("GPS GPSLongitudeRef"))

    if not tags:       anomalies.append("⚠ No EXIF metadata — possible intentional stripping")
    if not timestamp:  anomalies.append("⚠ Missing original timestamp")
    if lat is None or lon is None: anomalies.append("⚠ Missing GPS coordinates")
    if software:       anomalies.append(f"⚠ Software tag: {software} — possible post-processing")
    if make is None and model is None and tags: anomalies.append("⚠ No camera make/model — suspicious")

    return {
        "file_name":    os.path.basename(path_str),
        "file_size_kb": round(file_size / 1024, 1),
        "format":       fmt,
        "sha256":       file_hash,
        "timestamp":    timestamp or "N/A",
        "camera_make":  make or "Unknown",
        "camera_model": model or "Unknown",
        "software":     software or "None",
        "gps_latitude": lat,
        "gps_longitude":lon,
        "has_exif":     bool(tags),
        "anomaly_flags":   " | ".join(anomalies) if anomalies else "None",
        "anomaly_count":   len(anomalies),
    }


# ─────────────────────────────────────────────
# WORKER THREAD
# ─────────────────────────────────────────────

class AnalysisWorker(QThread):
    progress     = pyqtSignal(int)
    log          = pyqtSignal(str)
    result_ready = pyqtSignal(list)
    finished     = pyqtSignal(str)

    def __init__(self, input_dir, output_dir):
        super().__init__()
        self.input_dir  = input_dir
        self.output_dir = output_dir

    def run(self):
        exts = {".jpg", ".jpeg", ".tiff", ".tif", ".png"}
        images = [p for p in Path(self.input_dir).iterdir() if p.suffix.lower() in exts]

        if not images:
            self.log.emit("[!] No images found in selected folder.")
            self.finished.emit("")
            return

        self.log.emit(f"[*] Found {len(images)} image(s). Starting analysis...")
        os.makedirs(self.output_dir, exist_ok=True)

        records = []
        for i, img in enumerate(images, 1):
            self.log.emit(f"[*] Analyzing: {img.name}")
            rec = extract_record(img)
            records.append(rec)

            gps_str = f"{rec['gps_latitude']}, {rec['gps_longitude']}" if rec['gps_latitude'] else "Not found"
            self.log.emit(f"    GPS: {gps_str}")
            self.log.emit(f"    Flags: {rec['anomaly_flags']}")
            self.progress.emit(int(i / len(images) * 80))

        # Save CSV
        csv_path = os.path.join(self.output_dir, "metadata_results.csv")
        df = pd.DataFrame(records)
        df.to_csv(csv_path, index=False)

        # Chain of custody CSV
        coc_path = os.path.join(self.output_dir, "chain_of_custody.csv")
        with open(coc_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["evidence_id","file_name","sha256","timestamp","gps","anomaly_flags","analyzed_at","analyst"])
            for j, r in enumerate(records, 1):
                gps = f"{r['gps_latitude']},{r['gps_longitude']}" if r['gps_latitude'] else "N/A"
                w.writerow([f"EVD-{j:03d}", r["file_name"], r["sha256"],
                            r["timestamp"], gps, r["anomaly_flags"],
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Forensic Tool GUI v2.0"])

        # JSON
        json_path = os.path.join(self.output_dir, "raw_metadata.json")
        with open(json_path, "w") as f:
            json.dump(records, f, indent=2, default=str)

        # HTML Report
        report_path = os.path.join(self.output_dir, "forensic_report.html")
        self._write_html_report(records, report_path)

        self.progress.emit(100)
        self.log.emit("=" * 55)
        self.log.emit(f"[+] Analysis complete! {len(records)} file(s) processed.")
        self.log.emit(f"[+] Report  : {report_path}")
        self.log.emit(f"[+] CSV     : {csv_path}")
        self.log.emit(f"[+] Chain   : {coc_path}")
        self.log.emit("=" * 55)
        self.result_ready.emit(records)
        self.finished.emit(self.output_dir)

    def _write_html_report(self, records, path):
        rows = ""
        for i, r in enumerate(records, 1):
            bg = "#fff0f0" if r["anomaly_count"] > 0 else "#f0fff4"
            flag_color = "#dc2626" if r["anomaly_count"] > 0 else "#16a34a"
            gps = f"{r['gps_latitude']}, {r['gps_longitude']}" if r['gps_latitude'] else "N/A"
            rows += f"""
            <tr style="background:{bg}">
                <td>EVD-{i:03d}</td>
                <td>{r['file_name']}</td>
                <td>{r['timestamp']}</td>
                <td>{r['camera_make']} {r['camera_model']}</td>
                <td>{gps}</td>
                <td style="color:{flag_color};font-weight:600">{r['anomaly_flags']}</td>
                <td style="font-family:monospace;font-size:10px">{r['sha256'][:32]}...</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Forensic Report — CET333</title>
<style>
  body{{font-family:Arial,sans-serif;background:#f8fafc;color:#1e293b;margin:0;padding:20px}}
  .header{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:white;padding:30px;border-radius:12px;margin-bottom:24px}}
  h1{{margin:0;font-size:24px}} p{{margin:4px 0;opacity:.8;font-size:13px}}
  table{{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)}}
  th{{background:#0f172a;color:white;padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:1px}}
  td{{padding:11px 16px;font-size:13px;border-bottom:1px solid #f1f5f9}}
  .footer{{margin-top:20px;text-align:center;font-size:12px;color:#94a3b8}}
</style></head><body>
<div class="header">
  <h1>🔍 Digital Forensic Report</h1>
  <p>Course: CET333 — Advanced Digital Forensics | Spring 2026</p>
  <p>Instructor: Dr. Ayman Taha | Elsewedy University of Technology</p>
  <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Analyst: Forensic Tool GUI v2.0</p>
  <p>Total Evidence: {len(records)} file(s)</p>
</div>
<table><thead><tr>
  <th>ID</th><th>File</th><th>Timestamp</th><th>Camera</th><th>GPS</th><th>Anomaly Flags</th><th>SHA-256</th>
</tr></thead><tbody>{rows}</tbody></table>
<div class="footer">CET333 Advanced Digital Forensics — Elsewedy University of Technology</div>
</body></html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)


# ─────────────────────────────────────────────
# MAIN WINDOW
# ─────────────────────────────────────────────

class ForensicGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 Digital Forensic Tool v2.0 — CET333")
        self.setMinimumSize(1000, 680)
        self.input_dir  = ""
        self.output_dir = ""
        self._build_ui()
        self._apply_dark_theme()

    def _apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', Arial; }
            QGroupBox { border: 1px solid #334155; border-radius: 8px; margin-top: 8px; padding-top: 8px; font-weight: 600; color: #94a3b8; }
            QGroupBox::title { subcontrol-origin: margin; padding: 0 6px; }
            QPushButton {
                background: #1e40af; color: white; border: none;
                border-radius: 6px; padding: 8px 18px; font-weight: 600; font-size: 13px;
            }
            QPushButton:hover { background: #2563eb; }
            QPushButton:disabled { background: #334155; color: #64748b; }
            QPushButton#btn_open { background: #0f766e; }
            QPushButton#btn_open:hover { background: #0d9488; }
            QPushButton#btn_report { background: #7c3aed; }
            QPushButton#btn_report:hover { background: #8b5cf6; }
            QLabel { color: #cbd5e1; }
            QLabel#lbl_title { color: #38bdf8; font-size: 20px; font-weight: 700; }
            QLabel#lbl_sub   { color: #64748b; font-size: 12px; }
            QLineEdit, QTextEdit {
                background: #1e293b; border: 1px solid #334155;
                border-radius: 6px; color: #e2e8f0; padding: 6px; font-family: Consolas, monospace; font-size: 12px;
            }
            QProgressBar {
                background: #1e293b; border: 1px solid #334155; border-radius: 6px;
                height: 14px; text-align: center; color: white; font-size: 11px;
            }
            QProgressBar::chunk { background: linear-gradient(90deg, #0ea5e9, #38bdf8); border-radius: 5px; }
            QTableWidget {
                background: #1e293b; border: 1px solid #334155; border-radius: 6px;
                gridline-color: #334155; font-size: 12px;
            }
            QTableWidget::item { padding: 6px; color: #cbd5e1; }
            QTableWidget::item:selected { background: #1e40af; }
            QHeaderView::section {
                background: #0f172a; color: #94a3b8; padding: 8px;
                border: none; border-bottom: 1px solid #334155; font-weight: 600; font-size: 11px;
            }
            QTabWidget::pane { border: 1px solid #334155; border-radius: 6px; }
            QTabBar::tab { background: #1e293b; color: #94a3b8; padding: 8px 18px; border-radius: 6px 6px 0 0; margin-right: 2px; }
            QTabBar::tab:selected { background: #1e40af; color: white; }
            QSplitter::handle { background: #334155; }
            QStatusBar { background: #0f172a; color: #64748b; font-size: 11px; border-top: 1px solid #334155; }
        """)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 8)
        main_layout.setSpacing(12)

        # ── Header ──
        header = QFrame()
        header.setStyleSheet("background:#1e293b;border-radius:10px;padding:4px;")
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(16, 10, 16, 10)
        title_col = QVBoxLayout()
        lbl_title = QLabel("🔍 Digital Forensic Tool v2.0")
        lbl_title.setObjectName("lbl_title")
        lbl_sub = QLabel("CET333 — Advanced Digital Forensics  |  Elsewedy University  |  Dr. Ayman Taha")
        lbl_sub.setObjectName("lbl_sub")
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_sub)
        h_lay.addLayout(title_col)
        h_lay.addStretch()
        main_layout.addWidget(header)

        # ── Folder Controls ──
        ctrl = QGroupBox("Evidence Setup")
        ctrl_lay = QHBoxLayout(ctrl)
        ctrl_lay.setSpacing(10)

        self.lbl_input = QLabel("📁  No input folder selected")
        btn_input = QPushButton("📂  Select Evidence Folder")
        btn_input.setObjectName("btn_open")
        btn_input.clicked.connect(self._pick_input)

        self.lbl_output = QLabel("💾  No output folder selected")
        btn_output = QPushButton("📂  Select Output Folder")
        btn_output.clicked.connect(self._pick_output)

        self.btn_run = QPushButton("▶  Run Analysis")
        self.btn_run.setEnabled(False)
        self.btn_run.clicked.connect(self._run_analysis)
        self.btn_run.setMinimumWidth(140)

        ctrl_lay.addWidget(btn_input)
        ctrl_lay.addWidget(self.lbl_input, 1)
        ctrl_lay.addWidget(btn_output)
        ctrl_lay.addWidget(self.lbl_output, 1)
        ctrl_lay.addWidget(self.btn_run)
        main_layout.addWidget(ctrl)

        # ── Progress ──
        self.progress = QProgressBar()
        self.progress.setValue(0)
        main_layout.addWidget(self.progress)

        # ── Tabs ──
        tabs = QTabWidget()

        # Tab 1: Results Table
        tab_table = QWidget()
        tbl_lay = QVBoxLayout(tab_table)
        tbl_lay.setContentsMargins(0, 8, 0, 0)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Evidence ID", "File Name", "Timestamp", "Camera",
            "GPS Coordinates", "Anomaly Flags", "SHA-256"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        tbl_lay.addWidget(self.table)
        tabs.addTab(tab_table, "📊  Results Table")

        # Tab 2: Log
        tab_log = QWidget()
        log_lay = QVBoxLayout(tab_log)
        log_lay.setContentsMargins(0, 8, 0, 0)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("Analysis log will appear here...")
        log_lay.addWidget(self.log_box)
        tabs.addTab(tab_log, "📋  Analysis Log")

        main_layout.addWidget(tabs)

        # ── Bottom Buttons ──
        bot = QHBoxLayout()
        self.btn_report = QPushButton("🌐  Open HTML Report")
        self.btn_report.setObjectName("btn_report")
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self._open_report)

        self.btn_map = QPushButton("🗺️  Open Map")
        self.btn_map.setEnabled(False)
        self.btn_map.clicked.connect(self._open_map)

        self.btn_csv = QPushButton("📊  Open CSV")
        self.btn_csv.setEnabled(False)
        self.btn_csv.clicked.connect(self._open_csv)

        btn_clear = QPushButton("🗑  Clear")
        btn_clear.clicked.connect(self._clear)

        bot.addWidget(self.btn_report)
        bot.addWidget(self.btn_map)
        bot.addWidget(self.btn_csv)
        bot.addStretch()
        bot.addWidget(btn_clear)
        main_layout.addLayout(bot)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready — Select evidence folder to begin.")

    # ── Slots ──
    def _pick_input(self):
        d = QFileDialog.getExistingDirectory(self, "Select Evidence Folder")
        if d:
            self.input_dir = d
            count = sum(1 for f in Path(d).iterdir() if f.suffix.lower() in {".jpg",".jpeg",".tiff",".tif",".png"})
            self.lbl_input.setText(f"📁  {d}  ({count} image(s))")
            if not self.output_dir:
                self.output_dir = os.path.join(d, "output")
                self.lbl_output.setText(f"💾  {self.output_dir}  (auto)")
            self._check_ready()

    def _pick_output(self):
        d = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if d:
            self.output_dir = d
            self.lbl_output.setText(f"💾  {d}")
            self._check_ready()

    def _check_ready(self):
        self.btn_run.setEnabled(bool(self.input_dir and self.output_dir))

    def _run_analysis(self):
        self.btn_run.setEnabled(False)
        self.progress.setValue(0)
        self.table.setRowCount(0)
        self.log_box.clear()
        self.status.showMessage("Analyzing...")

        self.worker = AnalysisWorker(self.input_dir, self.output_dir)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.log.connect(self._append_log)
        self.worker.result_ready.connect(self._populate_table)
        self.worker.finished.connect(self._on_done)
        self.worker.start()

    def _append_log(self, msg):
        self.log_box.append(msg)

    def _populate_table(self, records):
        self.table.setRowCount(len(records))
        for i, r in enumerate(records):
            gps = f"{r['gps_latitude']}, {r['gps_longitude']}" if r['gps_latitude'] else "Not found"
            items = [
                f"EVD-{i+1:03d}",
                r["file_name"],
                r["timestamp"],
                f"{r['camera_make']} {r['camera_model']}",
                gps,
                r["anomaly_flags"],
                r["sha256"][:32] + "..."
            ]
            for j, val in enumerate(items):
                item = QTableWidgetItem(str(val))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                if j == 5 and r["anomaly_count"] > 0:
                    item.setForeground(QColor("#f87171"))
                elif j == 5:
                    item.setForeground(QColor("#4ade80"))
                if j == 4 and r['gps_latitude'] is None:
                    item.setForeground(QColor("#f87171"))
                self.table.setItem(i, j, item)

    def _on_done(self, out_dir):
        self.btn_run.setEnabled(True)
        if out_dir:
            self.btn_report.setEnabled(True)
            self.btn_map.setEnabled(True)
            self.btn_csv.setEnabled(True)
            self.status.showMessage(f"✅ Analysis complete! Output saved to: {out_dir}")
        else:
            self.status.showMessage("⚠ No images found.")

    def _open_report(self):
        p = os.path.join(self.output_dir, "forensic_report.html")
        if os.path.exists(p):
            os.startfile(p)

    def _open_map(self):
        p = os.path.join(self.output_dir, "map.html")
        if os.path.exists(p):
            os.startfile(p)
        else:
            QMessageBox.information(self, "Map", "Run the main forensic_tool.py to generate the interactive map.")

    def _open_csv(self):
        p = os.path.join(self.output_dir, "metadata_results.csv")
        if os.path.exists(p):
            os.startfile(p)

    def _clear(self):
        self.table.setRowCount(0)
        self.log_box.clear()
        self.progress.setValue(0)
        self.status.showMessage("Cleared.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Forensic Tool v2.0")
    window = ForensicGUI()
    window.show()
    sys.exit(app.exec_())
'''

with open('/home/user/forensic_gui.py', 'w', encoding='utf-8') as f:
    f.write(gui_code)

import os
print(f"Saved! Size: {os.path.getsize('/home/user/forensic_gui.py')} bytes")